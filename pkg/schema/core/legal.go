package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "legal",
		Name:        "Legal",
		Description: "Court orders, legal authority documents, and immigration status",
		Icon:        "scale",
	})

	for _, s := range []schema.Schema{
		{ID: "legal.court-orders", CategoryID: "legal", Name: "Court Orders", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "orderType", Type: "string", Required: true},
				{Name: "court", Type: "string"},
				{Name: "orderDate", Type: "date"},
				{Name: "caseNumber", Type: "string"},
			}},
		{ID: "legal.poa", CategoryID: "legal", Name: "Power of Attorney", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "poaType", Type: "string", Required: true, Description: "e.g. Enduring, General"},
				{Name: "grantor", Type: "string"},
				{Name: "attorney", Type: "string"},
				{Name: "executionDate", Type: "date"},
			}},
		{ID: "legal.will-estate", CategoryID: "legal", Name: "Will & Estate Documents", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "documentType", Type: "string", Required: true},
				{Name: "executionDate", Type: "date"},
				{Name: "notarisedBy", Type: "string"},
			}},
		{ID: "legal.immigration-status", CategoryID: "legal", Name: "Immigration Status", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "visaType", Type: "string"},
				{Name: "visaNumber", Type: "string"},
				{Name: "expiryDate", Type: "date"},
				{Name: "conditions", Type: "string"},
			}},
		// Extra-sensitive: always requires individual explicit consent.
		{ID: "legal.criminal-record", CategoryID: "legal", Name: "Criminal Record", Source: schema.SourceCore,
			ExtraSensitive: true,
			Claims: []schema.ClaimDefinition{
				{Name: "recordType", Type: "string", Description: "e.g. clean, spent, conviction"},
				{Name: "issuingAuthority", Type: "string"},
				{Name: "issuedDate", Type: "date"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
