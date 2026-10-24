package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "property",
		Name:        "Property & Assets",
		Description: "Real estate, vehicles, and other asset ownership records",
		Icon:        "home",
	})

	for _, s := range []schema.Schema{
		{ID: "property.real-estate", CategoryID: "property", Name: "Real Estate", Source: schema.SourceCore,
			Description: "Land and property ownership (LINZ in NZ)",
			Claims: []schema.ClaimDefinition{
				{Name: "titleReference", Type: "string", Required: true},
				{Name: "legalDescription", Type: "string"},
				{Name: "address", Type: "string"},
				{Name: "registeredDate", Type: "date"},
				{Name: "ownershipType", Type: "string", Description: "e.g. freehold, leasehold, cross-lease"},
			}},
		{ID: "property.vehicles", CategoryID: "property", Name: "Vehicles", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "registration", Type: "string", Required: true},
				{Name: "make", Type: "string"},
				{Name: "model", Type: "string"},
				{Name: "year", Type: "number"},
				{Name: "vin", Type: "string"},
			}},
		{ID: "property.assets", CategoryID: "property", Name: "Other Assets", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "assetType", Type: "string", Required: true},
				{Name: "description", Type: "string"},
				{Name: "estimatedValue", Type: "number"},
				{Name: "currency", Type: "string"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
