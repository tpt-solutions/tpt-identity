package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "finance",
		Name:        "Finance",
		Description: "Banking, income, tax, credit, and financial account credentials",
		Icon:        "banknote",
	})

	for _, s := range []schema.Schema{
		{ID: "finance.bank-account", CategoryID: "finance", Name: "Bank Account", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "bankName", Type: "string", Required: true},
				{Name: "accountNumber", Type: "string", Required: true},
				{Name: "accountType", Type: "string"},
				{Name: "currency", Type: "string"},
			}},
		{ID: "finance.income", CategoryID: "finance", Name: "Income Verification", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "employerName", Type: "string"},
				{Name: "annualIncome", Type: "number"},
				{Name: "currency", Type: "string"},
				{Name: "periodEndDate", Type: "date"},
			}},
		{ID: "finance.tax-records", CategoryID: "finance", Name: "Tax Records", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "taxYear", Type: "string", Required: true},
				{Name: "filingStatus", Type: "string"},
				{Name: "jurisdiction", Type: "string"},
			}},
		{ID: "finance.credit-history", CategoryID: "finance", Name: "Credit History", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "creditScore", Type: "number"},
				{Name: "bureau", Type: "string"},
				{Name: "reportDate", Type: "date"},
			}},
		{ID: "finance.benefits", CategoryID: "finance", Name: "Benefit Entitlements", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "benefitType", Type: "string", Required: true},
				{Name: "issuingAuthority", Type: "string"},
				{Name: "validFrom", Type: "date"},
				{Name: "validTo", Type: "date"},
			}},
		{ID: "finance.insurance-policies", CategoryID: "finance", Name: "Insurance Policies", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "insurerName", Type: "string", Required: true},
				{Name: "policyNumber", Type: "string", Required: true},
				{Name: "policyType", Type: "string"},
				{Name: "expiryDate", Type: "date"},
			}},
		{ID: "finance.investments", CategoryID: "finance", Name: "Investment Accounts", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "providerName", Type: "string", Required: true},
				{Name: "accountType", Type: "string"},
				{Name: "currency", Type: "string"},
			}},
		{ID: "finance.property-ownership", CategoryID: "finance", Name: "Property Ownership", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "titleReference", Type: "string"},
				{Name: "legalDescription", Type: "string"},
				{Name: "registeredDate", Type: "date"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
