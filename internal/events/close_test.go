package events_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// A subscription on a private address fails every attempt quickly, but its retries keep a delivery
// in flight for several seconds. That lets Close be tested against a real in-flight delivery.
func busWithFailingSubscription(t *testing.T) *events.Bus {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SaveWebhookSubscription(context.Background(), &store.WebhookSubscription{
		ID: "sub-1", URL: "http://10.0.0.1/hook", SigningSecret: "secret-value-0123456789",
		EventTypes: []string{"credential.issued"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return events.NewBus(st, slog.Default())
}

// Close on an idle bus returns at once.
func TestCloseIdleBus(t *testing.T) {
	bus := busWithFailingSubscription(t)
	start := time.Now()
	if err := bus.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("idle close took %v", time.Since(start))
	}
}

// Close waits for an in-flight delivery and then returns nil, once the deliveries have finished.
func TestCloseWaitsForInFlightDelivery(t *testing.T) {
	bus := busWithFailingSubscription(t)
	bus.Publish(context.Background(), "credential.issued", map[string]string{"id": "c-1"})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := bus.Close(ctx); err != nil {
		t.Fatalf("close after deliveries finished: %v", err)
	}
}

// A deadline shorter than the retries returns an error at the deadline, not after the retries.
func TestCloseDeadlineCancelsRetries(t *testing.T) {
	bus := busWithFailingSubscription(t)
	bus.Publish(context.Background(), "credential.issued", map[string]string{"id": "c-2"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := bus.Close(ctx); err == nil {
		t.Error("close with a short deadline returned nil while deliveries were in flight")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("close did not return at its deadline: %v", time.Since(start))
	}
}
