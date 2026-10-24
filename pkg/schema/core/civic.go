package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "civic",
		Name:        "Civic & Government",
		Description: "Electoral, taxation, government benefits, and business registration",
		Icon:        "landmark",
	})

	for _, s := range []schema.Schema{
		{ID: "civic.electoral-roll", CategoryID: "civic", Name: "Electoral Roll", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "electoralDistrict", Type: "string"},
				{Name: "maoriRollElector", Type: "boolean"},
				{Name: "enrolledDate", Type: "date"},
			}},
		{ID: "civic.benefits-entitlements", CategoryID: "civic", Name: "Government Benefit Entitlements", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "benefitType", Type: "string", Required: true},
				{Name: "issuingAgency", Type: "string"},
				{Name: "validFrom", Type: "date"},
				{Name: "validTo", Type: "date"},
			}},
		{ID: "civic.tax-filing", CategoryID: "civic", Name: "Tax Filing Status", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "taxYear", Type: "string", Required: true},
				{Name: "filingStatus", Type: "string"},
				{Name: "jurisdiction", Type: "string"},
			}},
		{ID: "civic.business-registration", CategoryID: "civic", Name: "Business Registration", Source: schema.SourceCore,
			Description: "Companies Office (NZ) and equivalent registries",
			Claims: []schema.ClaimDefinition{
				{Name: "companyNumber", Type: "string", Required: true},
				{Name: "companyName", Type: "string", Required: true},
				{Name: "registrationDate", Type: "date"},
				{Name: "companyStatus", Type: "string"},
				{Name: "nzbn", Type: "string", Description: "New Zealand Business Number"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
