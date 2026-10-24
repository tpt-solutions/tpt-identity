package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// The store accepts one response per request, and prunes expired requests with their responses.
func TestOID4VPOneResponseAndPruning(t *testing.T) {
	ctx := context.Background()
	st := newStatusStore(t)

	if err := st.SaveOID4VPRequest(ctx, "req-1", []byte(`{"id":"req-1"}`), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveOID4VPRequest(ctx, "req-1", []byte(`{}`), time.Now().Add(time.Hour)); err != store.ErrOID4VPRequestExists {
		t.Errorf("reused request id: want ErrOID4VPRequestExists, got %v", err)
	}

	if err := st.SaveOID4VPResponse(ctx, "req-1", []byte(`{"vp":1}`)); err != nil {
		t.Fatalf("first response: %v", err)
	}
	if err := st.SaveOID4VPResponse(ctx, "req-1", []byte(`{"vp":2}`)); err != store.ErrOID4VPResponseExists {
		t.Errorf("second response: want ErrOID4VPResponseExists, got %v", err)
	}
	got, err := st.GetOID4VPResponse(ctx, "req-1")
	if err != nil || string(got) != `{"vp":1}` {
		t.Errorf("stored response = %q, %v; want the first one", got, err)
	}

	if err := st.SaveOID4VPRequest(ctx, "old", []byte(`{}`), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteExpiredOID4VP(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetOID4VPRequest(ctx, "old"); err != store.ErrNotFound {
		t.Errorf("expired request not pruned: %v", err)
	}
	if _, _, err := st.GetOID4VPRequest(ctx, "req-1"); err != nil {
		t.Errorf("live request pruned: %v", err)
	}
}
