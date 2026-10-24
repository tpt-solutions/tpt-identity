package recovery

import (
	"bytes"
	"testing"
)

func TestSplitCombineAnyThresholdSubset(t *testing.T) {
	secret := []byte("recovery secret material")
	shares, err := Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(shares) != 3 {
		t.Fatalf("want 3 shares, got %d", len(shares))
	}
	pairs := [][]Share{{shares[0], shares[1]}, {shares[0], shares[2]}, {shares[1], shares[2]}}
	for _, pair := range pairs {
		got, err := Combine(pair)
		if err != nil {
			t.Fatalf("combine: %v", err)
		}
		if !bytes.Equal(got, secret) {
			t.Errorf("combine(%d,%d) = %q, want %q", pair[0].Index, pair[1].Index, got, secret)
		}
	}
}

func TestCombineRejectsDuplicateIndex(t *testing.T) {
	shares, err := Split([]byte("secret"), 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if _, err := Combine([]Share{shares[0], shares[0]}); err == nil {
		t.Error("duplicate share index was accepted")
	}
}

func TestCombineRejectsZeroIndex(t *testing.T) {
	shares, err := Split([]byte("secret"), 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	bad := Share{Index: 0, Value: shares[0].Value}
	if _, err := Combine([]Share{bad, shares[1]}); err == nil {
		t.Error("share index 0 was accepted")
	}
}

func TestCombineNeedsTwoShares(t *testing.T) {
	shares, err := Split([]byte("secret"), 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if _, err := Combine(shares[:1]); err == nil {
		t.Error("single share was accepted")
	}
}

func TestShareHexRoundTrip(t *testing.T) {
	shares, err := Split([]byte("secret"), 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	parsed, err := ParseHex(shares[0].Hex())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Index != shares[0].Index || !bytes.Equal(parsed.Value, shares[0].Value) {
		t.Errorf("hex round trip changed the share")
	}
}
