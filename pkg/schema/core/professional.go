package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "professional",
		Name:        "Professional",
		Description: "Qualifications, professional registrations, and employment credentials",
		Icon:        "briefcase",
	})

	for _, s := range []schema.Schema{
		{ID: "professional.qualifications", CategoryID: "professional", Name: "Qualifications", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "qualification", Type: "string", Required: true},
				{Name: "awardingBody", Type: "string", Required: true},
				{Name: "awardDate", Type: "date"},
				{Name: "level", Type: "string", Description: "e.g. NZQF Level 7"},
			}},
		{ID: "professional.registrations", CategoryID: "professional", Name: "Professional Registrations", Source: schema.SourceCore,
			Description: "HPCA, NZLS, NZIA, IPENZ and similar regulatory body registrations",
			Claims: []schema.ClaimDefinition{
				{Name: "registrationBody", Type: "string", Required: true},
				{Name: "registrationNumber", Type: "string", Required: true},
				{Name: "registrationClass", Type: "string"},
				{Name: "expiryDate", Type: "date"},
				{Name: "scope", Type: "string"},
			}},
		{ID: "professional.employment", CategoryID: "professional", Name: "Employment History", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "employerName", Type: "string", Required: true},
				{Name: "jobTitle", Type: "string"},
				{Name: "startDate", Type: "date"},
				{Name: "endDate", Type: "date"},
			}},
		{ID: "professional.practising-certificates", CategoryID: "professional", Name: "Practising Certificates", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "issuingBody", Type: "string", Required: true},
				{Name: "certificateNumber", Type: "string", Required: true},
				{Name: "validFrom", Type: "date", Required: true},
				{Name: "validTo", Type: "date", Required: true},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
