package authn_test

import (
	"context"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/authn"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
)

const duressTestDID = "did:peer:duress-holder"

func TestDuressEnrolThenCheck(t *testing.T) {
	ctx := context.Background()
	m := authn.NewDuressManager(storetest.New(t))

	if err := m.Enrol(ctx, duressTestDID, "under-duress-phrase"); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if ok, err := m.CheckDuress(ctx, duressTestDID, "under-duress-phrase"); err != nil || !ok {
		t.Errorf("duress passphrase: want match, got %v, %v", ok, err)
	}
	if ok, err := m.CheckDuress(ctx, duressTestDID, "the-normal-password"); err != nil || ok {
		t.Errorf("normal passphrase: want no match, got %v, %v", ok, err)
	}
}

func TestDuressNotEnrolledNeverMatches(t *testing.T) {
	m := authn.NewDuressManager(storetest.New(t))
	if ok, err := m.CheckDuress(context.Background(), duressTestDID, "anything"); err != nil || ok {
		t.Errorf("no duress enrolled: want no match, got %v, %v", ok, err)
	}
}

func TestDuressEnrolRejectsEmptyPassphrase(t *testing.T) {
	m := authn.NewDuressManager(storetest.New(t))
	if err := m.Enrol(context.Background(), duressTestDID, ""); err == nil {
		t.Error("empty duress passphrase: want error")
	}
}

// Enrolling again replaces the old passphrase, so the old one no longer signals duress.
func TestDuressReEnrolReplacesPassphrase(t *testing.T) {
	ctx := context.Background()
	m := authn.NewDuressManager(storetest.New(t))

	if err := m.Enrol(ctx, duressTestDID, "first-phrase"); err != nil {
		t.Fatalf("enrol first: %v", err)
	}
	if err := m.Enrol(ctx, duressTestDID, "second-phrase"); err != nil {
		t.Fatalf("enrol second: %v", err)
	}
	if ok, _ := m.CheckDuress(ctx, duressTestDID, "first-phrase"); ok {
		t.Error("replaced passphrase still matches")
	}
	if ok, _ := m.CheckDuress(ctx, duressTestDID, "second-phrase"); !ok {
		t.Error("new passphrase does not match")
	}
}

func TestDuressRemoveClearsConfig(t *testing.T) {
	ctx := context.Background()
	m := authn.NewDuressManager(storetest.New(t))

	if err := m.Enrol(ctx, duressTestDID, "under-duress-phrase"); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := m.Remove(ctx, duressTestDID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if ok, _ := m.CheckDuress(ctx, duressTestDID, "under-duress-phrase"); ok {
		t.Error("removed duress passphrase still matches")
	}
}
