package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "travel",
		Name:        "Travel",
		Description: "Passports, visas, vaccination certificates, and travel insurance",
		Icon:        "plane",
	})

	for _, s := range []schema.Schema{
		{ID: "travel.passport", CategoryID: "travel", Name: "Passport", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "passportNumber", Type: "string", Required: true},
				{Name: "issuingCountry", Type: "string", Required: true},
				{Name: "issueDate", Type: "date"},
				{Name: "expiryDate", Type: "date", Required: true},
			}},
		{ID: "travel.visas", CategoryID: "travel", Name: "Visas", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "visaType", Type: "string", Required: true},
				{Name: "issuingCountry", Type: "string", Required: true},
				{Name: "visaNumber", Type: "string"},
				{Name: "validFrom", Type: "date"},
				{Name: "validTo", Type: "date"},
				{Name: "conditions", Type: "string"},
			}},
		{ID: "travel.vaccination-certs", CategoryID: "travel", Name: "International Vaccination Certificates", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "vaccine", Type: "string", Required: true},
				{Name: "administeredDate", Type: "date", Required: true},
				{Name: "issuingAuthority", Type: "string"},
				{Name: "certificateNumber", Type: "string"},
			}},
		{ID: "travel.travel-insurance", CategoryID: "travel", Name: "Travel Insurance", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "insurerName", Type: "string", Required: true},
				{Name: "policyNumber", Type: "string", Required: true},
				{Name: "coverageStart", Type: "date"},
				{Name: "coverageEnd", Type: "date"},
				{Name: "coverageRegions", Type: "string"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
