package marketplace

import (
	"sync"
	"testing"
)

func findEntry(t *testing.T, r *Registry, issuer, schema string) *Entry {
	t.Helper()
	for _, e := range r.List() {
		if e.IssuerDID == issuer && e.SchemaID == schema {
			return e
		}
	}
	t.Fatalf("no entry for %s / %s", issuer, schema)
	return nil
}

func TestRegisterAddsEntryWithName(t *testing.T) {
	r := New()
	r.Register("did:web:uni.example", "education.degree", "Degree")
	e := findEntry(t, r, "did:web:uni.example", "education.degree")
	if e.SchemaName != "Degree" || e.IssuedCount != 0 {
		t.Errorf("got %+v", e)
	}
}

func TestRegisterDoesNotResetCount(t *testing.T) {
	r := New()
	r.Register("did:web:a.example", "identity.legal-name", "Legal name")
	r.RecordIssuance("did:web:a.example", "identity.legal-name")
	r.Register("did:web:a.example", "identity.legal-name", "Renamed")
	if got := findEntry(t, r, "did:web:a.example", "identity.legal-name").IssuedCount; got != 1 {
		t.Errorf("re-registering reset the count: got %d", got)
	}
}

func TestRecordIssuanceAutoRegisters(t *testing.T) {
	r := New()
	r.RecordIssuance("did:web:b.example", "healthcare.nhi-credential")
	r.RecordIssuance("did:web:b.example", "healthcare.nhi-credential")
	if got := findEntry(t, r, "did:web:b.example", "healthcare.nhi-credential").IssuedCount; got != 2 {
		t.Errorf("want count 2, got %d", got)
	}
}

func TestListReturnsSnapshot(t *testing.T) {
	r := New()
	r.RecordIssuance("did:web:c.example", "identity.legal-name")
	snap := r.List()
	snap[0].IssuedCount = 999
	if got := findEntry(t, r, "did:web:c.example", "identity.legal-name").IssuedCount; got != 1 {
		t.Errorf("mutating a snapshot changed the registry: got %d", got)
	}
}

func TestConcurrentIssuanceIsCounted(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.RecordIssuance("did:web:d.example", "identity.legal-name")
		}()
	}
	wg.Wait()
	if got := findEntry(t, r, "did:web:d.example", "identity.legal-name").IssuedCount; got != 50 {
		t.Errorf("want 50, got %d", got)
	}
}
