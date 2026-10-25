package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/pkg/consent"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// The tests in this file pin the behaviour every Store backend must share. storetest runs them on
// SQLite, and on PostgreSQL when TPT_TEST_POSTGRES_DSN is set.

func TestIdentityRoundTripKeepsTenant(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	now := time.Now().UTC().Truncate(time.Second)

	id := &store.Identity{DID: "did:key:z6MkContract", Method: "key", Role: "user", TenantID: "acme", CreatedAt: now, UpdatedAt: now}
	if err := st.SaveIdentity(ctx, id); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := st.GetIdentity(ctx, id.DID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TenantID != "acme" || got.Role != "user" {
		t.Errorf("round trip: got tenant %q role %q", got.TenantID, got.Role)
	}

	got.Role = "suspended"
	if err := st.UpdateIdentity(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := st.GetIdentity(ctx, id.DID)
	if again.Role != "suspended" {
		t.Errorf("update not persisted: role %q", again.Role)
	}

	_, total, err := st.ListIdentities(ctx, 10, 0)
	if err != nil || total != 1 {
		t.Errorf("list: want total 1, got %d (%v)", total, err)
	}
	if _, err := st.GetIdentity(ctx, "did:key:z6MkMissing"); err == nil {
		t.Error("get missing identity: want error")
	}
}

func TestClientLifecycle(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)

	c := &store.OIDCClient{
		ClientID:                "client-contract",
		ClientName:              "Contract RP",
		RedirectURIs:            []string{"https://rp.example/cb", "https://rp.example/cb2"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		CreatedAt:               time.Now().UTC().Truncate(time.Second),
	}
	if err := st.SaveClient(ctx, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := st.GetClient(ctx, c.ClientID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.RedirectURIs) != 2 || len(got.GrantTypes) != 2 {
		t.Errorf("list fields did not round-trip: %+v", got)
	}

	clients, err := st.ListClients(ctx)
	if err != nil || len(clients) != 1 {
		t.Errorf("list: want 1 client, got %d (%v)", len(clients), err)
	}
	if err := st.DeleteClient(ctx, c.ClientID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetClient(ctx, c.ClientID); err == nil {
		t.Error("deleted client still returned")
	}
}

func TestWebhookListFiltersByEventType(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	now := time.Now().UTC()

	subs := []*store.WebhookSubscription{
		{ID: "wh_issued", URL: "https://a.example/hook", EventTypes: []string{"credential.issued"}, SigningSecret: "s1", CreatedAt: now},
		{ID: "wh_all", URL: "https://b.example/hook", EventTypes: []string{"*"}, SigningSecret: "s2", CreatedAt: now},
		{ID: "wh_consent", URL: "https://c.example/hook", EventTypes: []string{"consent.granted"}, SigningSecret: "s3", CreatedAt: now},
	}
	for _, s := range subs {
		if err := st.SaveWebhookSubscription(ctx, s); err != nil {
			t.Fatalf("save %s: %v", s.ID, err)
		}
	}

	matched, err := st.ListWebhookSubscriptions(ctx, "credential.issued")
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if !hasWebhook(matched, "wh_issued") || !hasWebhook(matched, "wh_all") || hasWebhook(matched, "wh_consent") {
		t.Errorf("filter credential.issued: got %v", webhookIDs(matched))
	}

	all, err := st.ListWebhookSubscriptions(ctx, "")
	if err != nil || len(all) != 3 {
		t.Errorf("empty event type: want all 3, got %d (%v)", len(all), err)
	}

	if err := st.DeleteWebhookSubscription(ctx, "wh_all"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetWebhookSubscription(ctx, "wh_all"); err == nil {
		t.Error("deleted subscription still returned")
	}
}

func hasWebhook(subs []*store.WebhookSubscription, id string) bool {
	for _, s := range subs {
		if s.ID == id {
			return true
		}
	}
	return false
}

func webhookIDs(subs []*store.WebhookSubscription) []string {
	ids := make([]string, 0, len(subs))
	for _, s := range subs {
		ids = append(ids, s.ID)
	}
	return ids
}

// Revocation keeps the row (NZ Privacy Act 2020 audit trail) and succeeds only once.
func TestGrantRevocationIsSoftAndOnce(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)

	g := &consent.Grant{
		ID:         "grant-contract",
		SubjectDID: "did:peer:subject",
		RelyingDID: "did:web:rp.example",
		Level:      consent.GrantSchema,
		ScopeID:    "identity.legal-name",
		GrantedAt:  time.Now().UTC(),
	}
	if err := st.SaveGrant(ctx, g); err != nil {
		t.Fatalf("save: %v", err)
	}

	first, err := st.RevokeGrant(ctx, g.ID, time.Now().UTC())
	if err != nil || !first {
		t.Fatalf("first revoke: want true, got %v (%v)", first, err)
	}
	second, err := st.RevokeGrant(ctx, g.ID, time.Now().UTC())
	if err != nil || second {
		t.Errorf("second revoke: want false, got %v (%v)", second, err)
	}

	kept, err := st.GetGrant(ctx, g.ID)
	if err != nil {
		t.Fatalf("get revoked grant: %v", err)
	}
	if kept.RevokedAt == nil {
		t.Error("revoked grant lost its RevokedAt")
	}
}

// An authorization code redeems once: the session is taken, so a second redemption finds nothing.
func TestAuthorizationCodeRedeemsOnce(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)

	sess := &store.OIDCSession{
		ID:         "sess-contract",
		SubjectDID: "did:peer:subject",
		ClientID:   "client-contract",
		Code:       "code-contract",
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Minute),
	}
	if err := st.SaveSession(ctx, sess); err != nil {
		t.Fatalf("save session: %v", err)
	}

	taken, err := st.TakeSessionByCode(ctx, "code-contract")
	if err != nil || taken.ID != sess.ID {
		t.Fatalf("first redemption: %v", err)
	}
	if _, err := st.TakeSessionByCode(ctx, "code-contract"); err == nil {
		t.Error("second redemption succeeded")
	}
	if _, err := st.GetSessionByCode(ctx, "code-contract"); err == nil {
		t.Error("session still reachable by code after redemption")
	}
}

// A refresh token can be marked used by exactly one caller.
func TestRefreshTokenMarkedUsedOnce(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)

	tok := &store.RefreshToken{
		Hash:       "hash-contract",
		FamilyID:   "family-contract",
		SubjectDID: "did:peer:subject",
		ClientID:   "client-contract",
		IssuedAt:   time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
	}
	if err := st.SaveRefreshToken(ctx, tok); err != nil {
		t.Fatalf("save: %v", err)
	}

	won, err := st.MarkRefreshTokenUsed(ctx, tok.Hash, time.Now().UTC())
	if err != nil || !won {
		t.Fatalf("first use: want true, got %v (%v)", won, err)
	}
	won, err = st.MarkRefreshTokenUsed(ctx, tok.Hash, time.Now().UTC())
	if err != nil || won {
		t.Errorf("second use: want false, got %v (%v)", won, err)
	}
}

func TestCredentialSaveListDelete(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)

	cred := &vc.VerifiableCredential{
		Credential: vc.Credential{ID: "urn:uuid:contract-cred",
			CredentialSubject: vc.CredentialSubject{ID: "did:peer:subject", Claims: map[string]string{"givenNames": "Alice"}}},
	}
	if err := st.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := st.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CredentialSubject.Claims["givenNames"] != "Alice" {
		t.Errorf("claims did not round-trip: %+v", got.CredentialSubject)
	}

	list, err := st.ListCredentials(ctx, "did:peer:subject")
	if err != nil || len(list) != 1 {
		t.Errorf("list by subject: want 1, got %d (%v)", len(list), err)
	}
	if err := st.DeleteCredential(ctx, cred.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetCredential(ctx, cred.ID); err == nil {
		t.Error("deleted credential still returned")
	}
}
