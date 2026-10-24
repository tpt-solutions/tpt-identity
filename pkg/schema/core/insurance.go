package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "insurance",
		Name:        "Insurance",
		Description: "Health, life, vehicle, home, and business insurance policies",
		Icon:        "shield",
	})

	for _, s := range []schema.Schema{
		{ID: "insurance.health", CategoryID: "insurance", Name: "Health Insurance", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "insurerName", Type: "string", Required: true},
				{Name: "policyNumber", Type: "string", Required: true},
				{Name: "coverageType", Type: "string"},
				{Name: "expiryDate", Type: "date"},
			}},
		{ID: "insurance.life", CategoryID: "insurance", Name: "Life Insurance", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "insurerName", Type: "string", Required: true},
				{Name: "policyNumber", Type: "string", Required: true},
				{Name: "sumInsured", Type: "number"},
				{Name: "currency", Type: "string"},
				{Name: "expiryDate", Type: "date"},
			}},
		{ID: "insurance.vehicle", CategoryID: "insurance", Name: "Vehicle Insurance", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "insurerName", Type: "string", Required: true},
				{Name: "policyNumber", Type: "string", Required: true},
				{Name: "vehicleRegistration", Type: "string"},
				{Name: "coverageType", Type: "string", Description: "e.g. comprehensive, third-party"},
				{Name: "expiryDate", Type: "date"},
			}},
		{ID: "insurance.home", CategoryID: "insurance", Name: "Home Insurance", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "insurerName", Type: "string", Required: true},
				{Name: "policyNumber", Type: "string", Required: true},
				{Name: "propertyAddress", Type: "string"},
				{Name: "coverageType", Type: "string"},
				{Name: "expiryDate", Type: "date"},
			}},
		{ID: "insurance.business", CategoryID: "insurance", Name: "Business Insurance", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "insurerName", Type: "string", Required: true},
				{Name: "policyNumber", Type: "string", Required: true},
				{Name: "coverageType", Type: "string"},
				{Name: "expiryDate", Type: "date"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
