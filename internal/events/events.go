// Package events provides a typed event bus for platform lifecycle events.
// Subscribers receive HTTP POST deliveries with HMAC-SHA256 signed payloads.
package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/netguard"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// Event types published by the platform.
const (
	CredentialIssued  = "credential.issued"
	CredentialRevoked = "credential.revoked"
	ConsentGranted    = "consent.granted"
	ConsentRevoked    = "consent.revoked"
	IdentityCreated   = "identity.created"
	SessionCreated    = "session.created"
	SessionRevoked    = "session.revoked"
)

// Event is a platform lifecycle event.
type Event struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	OccuredAt string `json:"occurred_at"` // RFC 3339
	Payload   any    `json:"payload"`
}

// LocalSubscriber is a function called synchronously on every Publish before
// webhook fan-out. Useful for in-process observers (audit log, metrics).
type LocalSubscriber func(ctx context.Context, event Event)

// DeliveryHook is called after every webhook delivery attempt with whether it succeeded.
type DeliveryHook func(success bool)

// Bus fans out events to registered webhook subscribers.
type Bus struct {
	st           store.Store
	logger       *slog.Logger
	client       *http.Client
	subscribers  []LocalSubscriber
	deliveryHook DeliveryHook
}

// NewBus creates a new event bus.
func NewBus(st store.Store, logger *slog.Logger) *Bus {
	return &Bus{
		st:     st,
		logger: logger,
		// Connects only to public addresses and never follows redirects.
		client: netguard.Client(10 * time.Second),
	}
}

// Ping sends a test event to a single subscription. Other subscribers do not receive it.
func (b *Bus) Ping(sub *store.WebhookSubscription) {
	body, err := json.Marshal(Event{
		ID:        randomEventID(),
		Type:      "webhook.ping",
		OccuredAt: time.Now().UTC().Format(time.RFC3339),
		Payload:   map[string]any{"webhook_id": sub.ID, "message": "Test delivery from tpt-identity."},
	})
	if err != nil {
		b.logger.Error("events: marshal ping", "err", err)
		return
	}
	go b.deliver(sub, body)
}

// Subscribe registers an in-process subscriber called on every Publish.
func (b *Bus) Subscribe(fn LocalSubscriber) {
	b.subscribers = append(b.subscribers, fn)
}

// SetDeliveryHook registers a callback invoked after every webhook delivery attempt.
func (b *Bus) SetDeliveryHook(fn DeliveryHook) {
	b.deliveryHook = fn
}

// Publish delivers the event to all matching webhook subscribers asynchronously.
func (b *Bus) Publish(ctx context.Context, eventType string, payload any) {
	event := Event{
		ID:        randomEventID(),
		Type:      eventType,
		OccuredAt: time.Now().UTC().Format(time.RFC3339),
		Payload:   payload,
	}
	body, err := json.Marshal(event)
	if err != nil {
		b.logger.Error("events: marshal", "err", err)
		return
	}

	// Notify in-process subscribers synchronously before webhook fan-out.
	for _, fn := range b.subscribers {
		fn(ctx, event)
	}

	subs, err := b.st.ListWebhookSubscriptions(ctx, eventType)
	if err != nil {
		b.logger.Error("events: list subscriptions", "err", err)
		return
	}

	for _, sub := range subs {
		go b.deliver(sub, body)
	}
}

// deliver attempts webhook delivery with up to 3 retries and exponential backoff.
func (b *Bus) deliver(sub *store.WebhookSubscription, body []byte) {
	if sub.SigningSecret == "" {
		// Subscriptions created before signing secrets were stored cannot be signed; skip them.
		b.logger.Warn("events: subscription has no signing secret; re-register it", "subscription", sub.ID)
		return
	}
	sig := computeHMAC(body, sub.SigningSecret)
	backoff := 2 * time.Second
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		req, err := http.NewRequest(http.MethodPost, sub.URL, bytes.NewReader(body))
		if err != nil {
			b.logger.Error("events: build request", "url", sub.URL, "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-TPT-Signature-256", "sha256="+sig)
		req.Header.Set("X-TPT-Event-ID", extractEventID(body))

		resp, err := b.client.Do(req)
		if err != nil {
			b.logger.Warn("events: delivery failed", "url", sub.URL, "attempt", attempt+1, "err", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if b.deliveryHook != nil {
				b.deliveryHook(true)
			}
			return
		}
		b.logger.Warn("events: non-2xx response", "url", sub.URL, "status", resp.StatusCode, "attempt", attempt+1)
	}
	b.logger.Error("events: delivery failed after 3 attempts", "url", sub.URL)
	if b.deliveryHook != nil {
		b.deliveryHook(false)
	}
}

// computeHMAC signs body with the subscription's raw signing secret, which the receiver
// also holds. Receivers verify X-TPT-Signature-256 with the same secret.
func computeHMAC(body []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func extractEventID(body []byte) string {
	var e struct{ ID string `json:"id"` }
	json.Unmarshal(body, &e)
	return e.ID
}

func randomEventID() string {
	return fmt.Sprintf("evt_%016x", time.Now().UnixNano())
}
