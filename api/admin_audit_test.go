package api_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/auditlog"
	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// An admin action is written to the verifiable audit log, not only to the request log.
func TestAdminSuspendIsAudited(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.Default()
	bus := events.NewBus(st, logger)
	auditlog.New(st, logger).Subscribe(bus)

	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:       testAPIKey,
		AdminAPIKey:  testAdminKey,
		Issuer:       testIssuer,
		SigningKey:   priv,
		SigningKeyID: testPlatformDID + "#signing-key-1",
		Store:        st,
		Events:       bus,
		Resolver:     resolver.New(time.Minute),
		OIDC:         oidc.NewProvider(testIssuer, priv, "test-key-1", st),
	})

	const target = "did:peer:audited-user"
	now := time.Now()
	if err := st.SaveIdentity(ctx, &store.Identity{DID: target, Method: "peer", Role: "user", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	w := do(t, srv, http.MethodPost, "/admin/v1/identities/"+target+"/suspend", "", bearer(testAdminKey))
	if w.Code != http.StatusOK {
		t.Fatalf("suspend: %d %s", w.Code, w.Body.String())
	}

	events, _, err := st.ListAuditEvents(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.EventType == "admin.identity.suspended" && strings.Contains(e.Payload, target) {
			return
		}
	}
	t.Errorf("no admin.identity.suspended entry for %s in the audit log (%d events)", target, len(events))
}
