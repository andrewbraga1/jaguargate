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

	// 4. Tamper with ciphertext in L1 cache and verify Get fails closed (never returning corrupted ciphertext)
	store.setL1("token_tampered", "corrupted_base64_ciphertext", 60*time.Second)
	if val, _, err := store.Get("token_tampered"); err == nil || val != "" {
		t.Fatalf("SECURITY FAILURE: corrupted AES-GCM ciphertext did not fail closed (val=%q, err=%v)", val, err)
	}
}

func TestHybridStoreMultiInstanceAndValidation(t *testing.T) {
	// 1. Missing key for redis must fail
	_, err := NewHybridStore(config.StateStoreConfig{
		Driver:       "redis",
		RedisURL:     "redis://127.0.0.1:6379",
		AESGCMKeyEnv: "NON_EXISTENT_ENV_KEY",
	})
	if err == nil {
		t.Fatal("expected error when redis driver is configured without a valid key in env")
	}

	// 2. Multi-instance simulation: two independent instances sharing the same key
	t.Setenv("SHARED_CLUSTER_AES_KEY", "super-secret-production-cluster-key-32b!")
	inst1, err := NewHybridStore(config.StateStoreConfig{
		Driver:       "memory",
		AESGCMKeyEnv: "SHARED_CLUSTER_AES_KEY",
	})
	if err != nil {
		t.Fatalf("inst1 creation failed: %v", err)
	}

	inst2, err := NewHybridStore(config.StateStoreConfig{
		Driver:       "memory",
		AESGCMKeyEnv: "SHARED_CLUSTER_AES_KEY",
	})
	if err != nil {
		t.Fatalf("inst2 creation failed: %v", err)
	}

	// Instance 1 encrypts
	cipherText, err := inst1.Encrypt("session_secret_data_42")
	if err != nil {
		t.Fatalf("inst1 encryption failed: %v", err)
	}

	// Instance 2 decrypts
	plainText, err := inst2.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("inst2 decryption failed: %v", err)
	}
	if plainText != "session_secret_data_42" {
		t.Errorf("expected 'session_secret_data_42', got %q", plainText)
	}

	// Instance 3 with different key must fail to decrypt
	t.Setenv("DIFFERENT_CLUSTER_AES_KEY", "different-secret-key-that-will-fail!!")
	inst3, _ := NewHybridStore(config.StateStoreConfig{
		Driver:       "memory",
		AESGCMKeyEnv: "DIFFERENT_CLUSTER_AES_KEY",
	})
	if _, err := inst3.Decrypt(cipherText); err == nil {
		t.Fatal("expected inst3 with different key to fail decryption")
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
