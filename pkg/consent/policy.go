package consent

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/schema"
)

// GrantLevel describes the scope of a consent grant.
type GrantLevel string

const (
	// GrantSchema grants access to a single schema (default, least-privilege).
	GrantSchema GrantLevel = "schema"
	// GrantCategory grants access to all non-extra-sensitive schemas in a category.
	// Requires explicit extra confirmation from the subject.
	GrantCategory GrantLevel = "category"
)

// Grant records that a subject has consented to share a schema or category with a relying party.
type Grant struct {
	ID         string     `json:"id"`
	SubjectDID string     `json:"subjectDid"`
	RelyingDID string     `json:"relyingDid"` // the party receiving access
	Level      GrantLevel `json:"level"`
	// ScopeID is either a schema ID ("healthcare.gp-records") or a category ID ("healthcare").
	ScopeID   string     `json:"scopeId"`
	GrantedAt time.Time  `json:"grantedAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// RevokedAt is set when the subject withdraws consent. Never deleted — preserved for
	// audit trail under NZ Privacy Act 2020.
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	// ExplicitlyConfirmed must be true for GrantCategory and all extra-sensitive schemas.
	ExplicitlyConfirmed bool `json:"explicitlyConfirmed"`
}

// Policy enforces least-privilege consent rules.
type Policy struct {
	mu     sync.RWMutex
	grants []Grant
}

// NewPolicy creates an empty Policy. In production, populate grants from the store.
func NewPolicy(grants []Grant) *Policy {
	return &Policy{grants: grants}
}

// CanAccess reports whether relyingDID may access schemaID on behalf of subjectDID.
// Extra-sensitive schemas are only accessible via an explicit individual grant.
func (p *Policy) CanAccess(subjectDID, relyingDID, schemaID string) error {
	s, err := schema.GetSchema(schemaID)
	if err != nil {
		return fmt.Errorf("policy: unknown schema %q", schemaID)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	for _, g := range p.grants {
		if g.SubjectDID != subjectDID || g.RelyingDID != relyingDID {
			continue
		}
		if g.RevokedAt != nil {
			continue
		}
		if g.ExpiresAt != nil && now.After(*g.ExpiresAt) {
			continue
		}
		switch g.Level {
		case GrantSchema:
			if g.ScopeID == schemaID {
				return nil
			}
		case GrantCategory:
			if g.ScopeID == s.CategoryID {
				// Category grants never cover extra-sensitive schemas.
				if s.ExtraSensitive {
					continue
				}
				if !g.ExplicitlyConfirmed {
					continue
				}
				return nil
			}
		}
	}
	if s.ExtraSensitive {
		return fmt.Errorf("policy: %q is extra-sensitive and requires an individual explicit grant", schemaID)
	}
	return fmt.Errorf("policy: %s has not granted %s access to %q", subjectDID, relyingDID, schemaID)
}

// AddGrant adds a grant to the in-memory policy.
// For extra-sensitive schemas or category grants, ExplicitlyConfirmed must be true.
func (p *Policy) AddGrant(g Grant) error {
	if err := validateGrant(g); err != nil {
		return err
	}
	p.mu.Lock()
	p.grants = append(p.grants, g)
	p.mu.Unlock()
	return nil
}

// RevokeGrant withdraws a grant by setting RevokedAt. The record is never deleted —
// the audit trail must be preserved for NZ Privacy Act 2020 compliance.
func (p *Policy) RevokeGrant(grantID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, g := range p.grants {
		if g.ID == grantID {
			if p.grants[i].RevokedAt != nil {
				return fmt.Errorf("policy: grant %q already revoked", grantID)
			}
			now := time.Now()
			p.grants[i].RevokedAt = &now
			_ = g // suppress unused warning
			return nil
		}
	}
	return fmt.Errorf("policy: grant %q not found", grantID)
}

// ValidateGrant checks a grant's required fields and the rules for its scope: the scope must
// exist, extra-sensitive schemas and category grants need explicit confirmation.
func ValidateGrant(g Grant) error {
	return validateGrant(g)
}

func validateGrant(g Grant) error {
	if g.SubjectDID == "" || g.RelyingDID == "" || g.ScopeID == "" {
		return errors.New("policy: grant missing required fields")
	}
	switch g.Level {
	case GrantSchema:
		s, err := schema.GetSchema(g.ScopeID)
		if err != nil {
			return fmt.Errorf("policy: %w", err)
		}
		if s.ExtraSensitive && !g.ExplicitlyConfirmed {
			return fmt.Errorf("policy: schema %q is extra-sensitive; ExplicitlyConfirmed must be true", g.ScopeID)
		}
	case GrantCategory:
		if _, err := schema.GetCategory(g.ScopeID); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
		if !g.ExplicitlyConfirmed {
			return errors.New("policy: category grants require ExplicitlyConfirmed=true")
		}
	default:
		return fmt.Errorf("policy: unknown grant level %q", g.Level)
	}
	return nil
}
