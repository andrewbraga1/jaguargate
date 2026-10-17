package state

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jaguargate/jaguargate/internal/config"
)

var (
	ErrKeyNotFound      = errors.New("key not found or expired")
	ErrRedisUnavailable = errors.New("redis state store unreachable")
)

type memItem struct {
	val       string
	expiresAt time.Time
}

// HybridStore provides an L1 in-memory store backed by an optional L2 Redis server
// using AES-256-GCM encryption and automatic Fail-Open resilience (JG-EXT-602).
type HybridStore struct {
	mu        sync.RWMutex
	l1        map[string]memItem
	driver    string
	redisAddr string
	redisPass string
	failOpen  bool
	aead      cipher.AEAD
}

// NewHybridStore initializes the L1/L2 state store from configuration.
func NewHybridStore(cfg config.StateStoreConfig) (*HybridStore, error) {
	s := &HybridStore{
		l1:       make(map[string]memItem, 512),
		driver:   strings.ToLower(strings.TrimSpace(cfg.Driver)),
		failOpen: cfg.FailOpenToLocalMemory,
	}
	if s.driver == "" {
		s.driver = "memory"
	}

	// Initialize optional AES-256-GCM cipher if key environment variable is set or driver is redis
	rawKey := ""
	if cfg.AESGCMKeyEnv != "" {
		rawKey = os.Getenv(cfg.AESGCMKeyEnv)
	}
	if rawKey == "" && s.driver == "redis" {
		// Fallback ephemeral per-process key so Redis data is never stored in plaintext
		var randomSeed [32]byte
		_, _ = rand.Read(randomSeed[:])
		rawKey = string(randomSeed[:])
	}
	if rawKey != "" {
		aead, err := newAES256GCM(rawKey)
		if err != nil {
			return nil, err
		}
		s.aead = aead
	}

	if s.driver == "redis" && cfg.RedisURL != "" {
		addr, pass := parseRedisURL(cfg.RedisURL)
		s.redisAddr = addr
		s.redisPass = pass
	}

	return s, nil
}

// Set stores a key-value pair with TTL. Returns warning code "JG-EXT-602" if Redis fails open to L1 memory.
func (s *HybridStore) Set(key, value string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	storedVal := value
	if s.aead != nil {
		enc, err := s.Encrypt(value)
		if err == nil {
			storedVal = enc
		}
	}

	// Always write to L1 local cache for sub-microsecond local reads
	s.setL1(key, storedVal, ttl)

	if s.driver == "redis" {
		if s.redisAddr == "" {
			if s.failOpen {
				return "JG-EXT-602", nil
			}
			return "JG-EXT-602", ErrRedisUnavailable
		}
		if err := s.redisSetEx(key, storedVal, int(ttl.Seconds())); err != nil {
			if s.failOpen {
				return "JG-EXT-602", nil
			}
			return "JG-EXT-602", err
		}
	}

	return "", nil
}

// Get retrieves and decrypts a key. Checks L1 first, then L2 Redis if configured.
func (s *HybridStore) Get(key string) (string, string, error) {
	if raw, ok := s.getL1(key); ok {
		if s.aead != nil {
			dec, err := s.Decrypt(raw)
			if err == nil {
				return dec, "", nil
			}
		}
		return raw, "", nil
	}

	if s.driver == "redis" {
		if s.redisAddr == "" {
			if s.failOpen {
				return "", "JG-EXT-602", ErrKeyNotFound
			}
			return "", "JG-EXT-602", ErrRedisUnavailable
		}
		raw, err := s.redisGet(key)
		if err != nil {
			if errors.Is(err, ErrKeyNotFound) {
				return "", "", ErrKeyNotFound
			}
			if s.failOpen {
				return "", "JG-EXT-602", ErrKeyNotFound
			}
			return "", "JG-EXT-602", err
		}

		// Populate L1 cache for subsequent hits
		s.setL1(key, raw, 60*time.Second)

		if s.aead != nil {
			dec, decErr := s.Decrypt(raw)
			if decErr == nil {
				return dec, "", nil
			}
		}
		return raw, "", nil
	}

	return "", "", ErrKeyNotFound
}

// Encrypt seals plaintext using AES-256-GCM with a random 12-byte nonce and returns Base64.
func (s *HybridStore) Encrypt(plaintext string) (string, error) {
	if s.aead == nil {
		return plaintext, nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens Base64 ciphertext sealed with AES-256-GCM.
func (s *HybridStore) Decrypt(encoded string) (string, error) {
	if s.aead == nil {
		return encoded, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	nonceSize := s.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *HybridStore) setL1(key, val string, ttl time.Duration) {
	s.mu.Lock()
	if len(s.l1) > 8192 {
		now := time.Now()
		for k, v := range s.l1 {
			if now.After(v.expiresAt) {
				delete(s.l1, k)
			}
		}
	}
	s.l1[key] = memItem{
		val:       val,
		expiresAt: time.Now().Add(ttl),
	}
	s.mu.Unlock()
}

func (s *HybridStore) getL1(key string) (string, bool) {
	s.mu.RLock()
	item, ok := s.l1[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(item.expiresAt) {
		return "", false
	}
	return item.val, true
}

func newAES256GCM(secret string) (cipher.AEAD, error) {
	// Derive deterministic 32-byte (256-bit) key via SHA-256 so any user secret length is valid
	keyHash := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func parseRedisURL(rawURL string) (string, string) {
	if !strings.Contains(rawURL, "://") {
		return rawURL, ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, ""
	}
	pass, _ := u.User.Password()
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":6379"
	}
	return host, pass
}

// Zero-dependency Redis Serialization Protocol (RESP) client with 25ms strict timeout.
func (s *HybridStore) redisSetEx(key, val string, ttlSec int) error {
	if ttlSec <= 0 {
		ttlSec = 60
	}
	conn, err := net.DialTimeout("tcp", s.redisAddr, 25*time.Millisecond)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Millisecond))

	reader := bufio.NewReader(conn)
	if s.redisPass != "" {
		if err := writeRESPCommand(conn, "AUTH", s.redisPass); err != nil {
			return err
		}
		if _, err := readRESPReply(reader); err != nil {
			return err
		}
	}

	if err := writeRESPCommand(conn, "SETEX", key, strconv.Itoa(ttlSec), val); err != nil {
		return err
	}
	_, err = readRESPReply(reader)
	return err
}

func (s *HybridStore) redisGet(key string) (string, error) {
	conn, err := net.DialTimeout("tcp", s.redisAddr, 25*time.Millisecond)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Millisecond))

	reader := bufio.NewReader(conn)
	if s.redisPass != "" {
		if err := writeRESPCommand(conn, "AUTH", s.redisPass); err != nil {
			return "", err
		}
		if _, err := readRESPReply(reader); err != nil {
			return "", err
		}
	}

	if err := writeRESPCommand(conn, "GET", key); err != nil {
		return "", err
	}
	return readRESPReply(reader)
}

func writeRESPCommand(w io.Writer, args ...string) error {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString("\r\n")
	for _, arg := range args {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(arg)))
		b.WriteString("\r\n")
		b.WriteString(arg)
		b.WriteString("\r\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func readRESPReply(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) == 0 {
		return "", errors.New("empty RESP reply")
	}

	switch line[0] {
	case '+': // Simple string (+OK)
		return line[1:], nil
	case '-': // Error (-ERR ...)
		return "", fmt.Errorf("redis error: %s", line[1:])
	case '$': // Bulk string ($len\r\npayload\r\n)
		length, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", err
		}
		if length == -1 {
			return "", ErrKeyNotFound
		}
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:length]), nil
	default:
		return line[1:], nil
	}
}
