// Package auditlog subscribes to the events bus and appends every event to
// the hash-chained audit_log table so tampering is detectable.
package auditlog

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// Logger appends all platform events to the verifiable audit log.
type Logger struct {
	store  store.Store
	logger *slog.Logger
}

// New creates an audit Logger.
func New(st store.Store, logger *slog.Logger) *Logger {
	return &Logger{store: st, logger: logger}
}

// Subscribe registers the audit logger as an in-process subscriber on the bus.
func (l *Logger) Subscribe(bus *events.Bus) {
	bus.Subscribe(l.handle)
}

func (l *Logger) handle(ctx context.Context, event events.Event) {
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		l.logger.Warn("auditlog: marshal payload", "event_type", event.Type, "err", err)
		payload = []byte("{}")
	}

	// The store links the event to the chain head within one transaction. A failed append is an
	// error: the event is not in the verifiable log.
	if _, err := l.store.AppendAuditEvent(ctx, event.Type, string(payload)); err != nil {
		l.logger.Error("auditlog: event not recorded", "event_type", event.Type, "err", err)
	}
}
