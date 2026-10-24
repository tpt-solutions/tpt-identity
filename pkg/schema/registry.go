package schema

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Source classifies where a schema came from.
type Source string

const (
	SourceCore       Source = "core"
	SourceCommunity  Source = "community"
	SourceThirdParty Source = "third-party"
)

// ClaimDefinition describes a single claim field within a schema.
type ClaimDefinition struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string", "date", "number", "boolean"
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
}

// Category is a top-level grouping of credential schemas (e.g. "healthcare").
type Category struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Icon        string `json:"icon,omitempty"`
}

// Schema describes a specific credential type within a category (e.g. "healthcare.gp-records").
type Schema struct {
	// ID is the dotted category.name identifier, e.g. "healthcare.gp-records".
	ID string `json:"id"`
	// CategoryID is the parent category, e.g. "healthcare".
	CategoryID string `json:"categoryId"`
	// Name is the human-readable label.
	Name string `json:"name"`
	// Description explains what credentials matching this schema contain.
	Description string `json:"description,omitempty"`
	// Version is the schema version (≥1). Incremented on breaking claim changes.
	// Issued VCs reference the versioned ID (e.g. "healthcare.gp-records-v1").
	Version int `json:"version"`
	// ExtraSensitive marks schemas that require individual explicit consent even when a
	// category-wide grant has been given. Examples: mental health, sexual health, criminal record.
	ExtraSensitive bool `json:"extraSensitive,omitempty"`
	// Claims defines the fields carried by credentials of this type.
	Claims []ClaimDefinition `json:"claims,omitempty"`
	// Source indicates whether this is a core, community, or third-party schema.
	Source Source `json:"source"`
}

// VersionedID returns the versioned schema identifier used in issued credentials,
// e.g. "healthcare.gp-records-v1". This is the ID that appears in VC credentialSchema.
func (s Schema) VersionedID() string {
	v := s.Version
	if v <= 0 {
		v = 1
	}
	return s.ID + "-v" + strconv.Itoa(v)
}

// BaseID strips the "-v{n}" suffix from a versioned schema ID, returning the base ID.
// If id has no version suffix it is returned unchanged.
func BaseID(id string) string {
	if idx := strings.LastIndex(id, "-v"); idx > 0 {
		suffix := id[idx+2:]
		if _, err := strconv.Atoi(suffix); err == nil {
			return id[:idx]
		}
	}
	return id
}

var (
	mu         sync.RWMutex
	categories = map[string]Category{}
	schemas    = map[string]Schema{}
)

// RegisterCategory adds a category to the global registry.
func RegisterCategory(c Category) {
	mu.Lock()
	defer mu.Unlock()
	categories[c.ID] = c
}

// RegisterSchema adds a schema to the global registry.
// Panics if a schema with the same ID is already registered.
func RegisterSchema(s Schema) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := schemas[s.ID]; ok {
		panic(fmt.Sprintf("schema: %q already registered", s.ID))
	}
	schemas[s.ID] = s
}

// GetSchema returns the schema for id, or an error if not found.
// Accepts both the base ID ("healthcare.gp-records") and the versioned ID
// ("healthcare.gp-records-v1"); versioned IDs are resolved to the registered schema.
func GetSchema(id string) (Schema, error) {
	mu.RLock()
	defer mu.RUnlock()
	if s, ok := schemas[id]; ok {
		return s, nil
	}
	// Try stripping the version suffix.
	base := baseID(id)
	if base != id {
		if s, ok := schemas[base]; ok {
			return s, nil
		}
	}
	return Schema{}, fmt.Errorf("schema: %q not found", id)
}

// baseID is the unexported fast-path version used inside the locked section.
func baseID(id string) string {
	if idx := strings.LastIndex(id, "-v"); idx > 0 {
		suffix := id[idx+2:]
		if _, err := strconv.Atoi(suffix); err == nil {
			return id[:idx]
		}
	}
	return id
}

// GetCategory returns the category for id.
func GetCategory(id string) (Category, error) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := categories[id]
	if !ok {
		return Category{}, fmt.Errorf("schema: category %q not found", id)
	}
	return c, nil
}

// SchemasForCategory returns all schemas belonging to the given category ID.
func SchemasForCategory(categoryID string) []Schema {
	mu.RLock()
	defer mu.RUnlock()
	var out []Schema
	for _, s := range schemas {
		if s.CategoryID == categoryID {
			out = append(out, s)
		}
	}
	return out
}

// AllCategories returns all registered categories.
func AllCategories() []Category {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Category, 0, len(categories))
	for _, c := range categories {
		out = append(out, c)
	}
	return out
}

// AllSchemas returns all registered schemas.
func AllSchemas() []Schema {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Schema, 0, len(schemas))
	for _, s := range schemas {
		out = append(out, s)
	}
	return out
}

// IsExtraSensitive reports whether the schema at id has ExtraSensitive set.
func IsExtraSensitive(id string) bool {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := schemas[id]
	return ok && s.ExtraSensitive
}
