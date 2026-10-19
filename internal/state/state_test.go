package state

import (
	"testing"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

func TestHybridStoreAESGCMAndRedisFailOpen(t *testing.T) {
	t.Setenv("JAGUARGATE_TEST_AES_KEY", "chave-secreta-curta-que-sera-esticada-via-sha256")

	// Configure Redis pointing to an unreachable port (127.0.0.1:6399) with FailOpenToLocalMemory=true
	cfg := config.StateStoreConfig{
		Driver:                "redis",
		RedisURL:              "redis://127.0.0.1:6399/0",
		AESGCMKeyEnv:          "JAGUARGATE_TEST_AES_KEY",
		FailOpenToLocalMemory: true,
	}

	store, err := NewHybridStore(cfg)
	if err != nil {
		t.Fatalf("failed to create HybridStore: %v", err)
	}

	// 1. Set should fail open to L1 memory and return warning code JG-EXT-602
	warnCode, err := store.Set("token_cpf_1", "123.456.789-01", 60*time.Second)
	if err != nil {
		t.Fatalf("expected Fail-Open Set to succeed without error, got %v", err)
	}
	if warnCode != "JG-EXT-602" {
		t.Errorf("expected warning code 'JG-EXT-602' on unreachable Redis, got %q", warnCode)
	}

	// 2. Verify L1 stored value is encrypted with AES-256-GCM at rest, not plaintext
	rawCipher, ok := store.getL1("token_cpf_1")
	if !ok || rawCipher == "123.456.789-01" {
		t.Fatalf("SECURITY FAILURE: value in L1/L2 store was not encrypted with AES-256-GCM: %q", rawCipher)
	}

	// 3. Get should decrypt from L1 cache seamlessly
	decrypted, _, err := store.Get("token_cpf_1")
	if err != nil {
		t.Fatalf("unexpected Get error: %v", err)
	}
	if decrypted != "123.456.789-01" {
		t.Errorf("expected decrypted value '123.456.789-01', got %q", decrypted)
	}
}

func BenchmarkAESGCMSealOpen(b *testing.B) {
	b.Setenv("BENCH_AES_KEY", "jaguargate-benchmark-aes-256-gcm-secret-key")
	store, err := NewHybridStore(config.StateStoreConfig{
		Driver:       "memory",
		AESGCMKeyEnv: "BENCH_AES_KEY",
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			enc, _ := store.Encrypt("123.456.789-01")
			_, _ = store.Decrypt(enc)
		}
	})
}
