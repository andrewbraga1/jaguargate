package telemetry

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

// WebhookEvent represents a structured security alert sent asynchronously to SIEM/Slack/Discord.
type WebhookEvent struct {
	Timestamp   string   `json:"timestamp"`
	Service     string   `json:"service"`
	Status      string   `json:"status"`
	Severity    string   `json:"severity"`
	Codes       []string `json:"codes"`
	Path        string   `json:"path"`
	PrunedTools int      `json:"pruned_tools,omitempty"`
}

// WebhookDispatcher manages a non-blocking buffered channel for asynchronous security alerts.
type WebhookDispatcher struct {
	queue        chan WebhookEvent
	client       *http.Client
	secret       string
	sentCount    atomic.Uint64
	droppedCount atomic.Uint64
	stopCh       chan struct{}
}

// NewWebhookDispatcher creates and starts a background non-blocking webhook worker.
func NewWebhookDispatcher() *WebhookDispatcher {
	return &WebhookDispatcher{
		queue: make(chan WebhookEvent, 256),
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
		secret: os.Getenv("JAGUARGATE_WEBHOOK_SECRET"),
		stopCh: make(chan struct{}),
	}
}

// Enqueue attempts to schedule a webhook alert in O(1) time without EVER blocking the caller goroutine.
func (d *WebhookDispatcher) Enqueue(evt WebhookEvent, cfg config.WebhooksConfig) bool {
	if d == nil || !cfg.Enabled {
		return false
	}

	targets := slices.Clone(cfg.Endpoints)
	if cfg.URL != "" && !slices.Contains(targets, cfg.URL) {
		targets = append(targets, cfg.URL)
	}
	if len(targets) == 0 {
		return false
	}

	triggers := cfg.TriggerOn
	if len(triggers) == 0 {
		triggers = cfg.Events
	}
	if len(triggers) > 0 && !slices.Contains(triggers, evt.Severity) && !slices.Contains(triggers, evt.Status) {
		return false
	}

	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if evt.Service == "" {
		evt.Service = "jaguargate"
	}

	hmacKey := d.secret
	if hmacKey == "" {
		hmacKey = cfg.SecretHmac
	}

	select {
	case d.queue <- evt:
		go d.deliver(evt, targets, hmacKey)
		return true
	default:
		d.droppedCount.Add(1)
		return false
	}
}

func (d *WebhookDispatcher) deliver(evt WebhookEvent, endpoints []string, hmacKey string) {
	defer func() {
		select {
		case <-d.queue:
		default:
		}
	}()

	payloadBytes, err := json.Marshal(evt)
	if err != nil {
		return
	}

	sig := ""
	if hmacKey != "" {
		mac := hmac.New(sha256.New, []byte(hmacKey))
		mac.Write(payloadBytes)
		sig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	for _, ep := range endpoints {
		if ep == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(payloadBytes))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "JaguarGate-Security-Webhook/1.0")
			if sig != "" {
				req.Header.Set("X-JaguarGate-Signature-256", sig)
			}
			resp, doErr := d.client.Do(req)
			if doErr == nil && resp != nil {
				_ = resp.Body.Close()
				d.sentCount.Add(1)
			}
		}
		cancel()
	}
}

// SentCount returns the total number of delivered webhook payloads.
func (d *WebhookDispatcher) SentCount() uint64 {
	return d.sentCount.Load()
}

// DroppedCount returns the number of alerts dropped due to backpressure.
func (d *WebhookDispatcher) DroppedCount() uint64 {
	return d.droppedCount.Load()
}
