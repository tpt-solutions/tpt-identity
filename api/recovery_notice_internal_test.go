package api

import "testing"

// Addresses may only be set for named guardians, and must parse as email addresses.
func TestValidateGuardianEmails(t *testing.T) {
	guardians := []string{"did:peer:g1", "did:peer:g2"}
	cases := map[string]struct {
		emails map[string]string
		ok     bool
	}{
		"none":           {nil, true},
		"named guardian": {map[string]string{"did:peer:g1": "g1@example.com"}, true},
		"not a guardian": {map[string]string{"did:peer:stranger": "s@example.com"}, false},
		"bad address":    {map[string]string{"did:peer:g1": "not-an-address"}, false},
		"empty address":  {map[string]string{"did:peer:g1": ""}, false},
	}
	for name, c := range cases {
		err := validateGuardianEmails(c.emails, guardians)
		if (err == nil) != c.ok {
			t.Errorf("%s: want ok=%v, got %v", name, c.ok, err)
		}
	}
}
