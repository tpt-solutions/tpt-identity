package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "social",
		Name:        "Social & Contact",
		Description: "Verified contact addresses, social graph, and reputation",
		Icon:        "users",
	})

	for _, s := range []schema.Schema{
		{ID: "social.verified-contacts", CategoryID: "social", Name: "Verified Contact Addresses", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "contactType", Type: "string", Required: true, Description: "e.g. email, did, phone"},
				{Name: "value", Type: "string", Required: true},
				{Name: "verifiedDate", Type: "date"},
			}},
		{ID: "social.social-graph", CategoryID: "social", Name: "Social Graph Connections", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "platform", Type: "string"},
				{Name: "profileUrl", Type: "string"},
				{Name: "verifiedDate", Type: "date"},
			}},
		{ID: "social.reputation", CategoryID: "social", Name: "Platform Reputation", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "platform", Type: "string", Required: true},
				{Name: "reputationScore", Type: "number"},
				{Name: "tier", Type: "string"},
				{Name: "evaluatedDate", Type: "date"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
