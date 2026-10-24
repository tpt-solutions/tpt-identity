package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "identity",
		Name:        "Identity",
		Description: "Core personal identity documents and government identifiers",
		Icon:        "id-card",
	})

	for _, s := range []schema.Schema{
		{ID: "identity.legal-name", CategoryID: "identity", Name: "Legal Name", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "givenNames", Type: "string", Required: true},
				{Name: "familyName", Type: "string", Required: true},
				{Name: "preferredName", Type: "string"},
			}},
		{ID: "identity.dob", CategoryID: "identity", Name: "Date of Birth", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "dateOfBirth", Type: "date", Required: true},
			}},
		{ID: "identity.address", CategoryID: "identity", Name: "Address", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "streetAddress", Type: "string", Required: true},
				{Name: "suburb", Type: "string"},
				{Name: "city", Type: "string", Required: true},
				{Name: "postcode", Type: "string"},
				{Name: "country", Type: "string", Required: true},
			}},
		{ID: "identity.passport", CategoryID: "identity", Name: "Passport", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "passportNumber", Type: "string", Required: true},
				{Name: "issuingCountry", Type: "string", Required: true},
				{Name: "expiryDate", Type: "date", Required: true},
			}},
		{ID: "identity.drivers-licence", CategoryID: "identity", Name: "Driver's Licence", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "licenceNumber", Type: "string", Required: true},
				{Name: "issuingAuthority", Type: "string", Required: true},
				{Name: "licenceClass", Type: "string"},
				{Name: "expiryDate", Type: "date", Required: true},
			}},
		{ID: "identity.nhi", CategoryID: "identity", Name: "NHI Number (NZ)", Source: schema.SourceCore,
			Description: "New Zealand National Health Index number",
			Claims: []schema.ClaimDefinition{
				{Name: "nhiNumber", Type: "string", Required: true},
			}},
		{ID: "identity.ird-number", CategoryID: "identity", Name: "IRD Number (NZ)", Source: schema.SourceCore,
			Description: "New Zealand Inland Revenue Department tax number",
			Claims: []schema.ClaimDefinition{
				{Name: "irdNumber", Type: "string", Required: true},
			}},
		{ID: "identity.realme-verified", CategoryID: "identity", Name: "RealMe Verified Identity (NZ)", Source: schema.SourceCore,
			Description: "Identity verified via the New Zealand Department of Internal Affairs RealMe service",
			Claims: []schema.ClaimDefinition{
				{Name: "flt", Type: "string", Required: true, Description: "RealMe Federated Login Token — pseudonymous per-service stable identifier"},
				{Name: "loaLevel", Type: "string", Required: true, Description: "Level of Assurance achieved: 1, 2, or 3"},
				{Name: "givenNames", Type: "string"},
				{Name: "familyName", Type: "string"},
				{Name: "dateOfBirth", Type: "date"},
				{Name: "addressLine1", Type: "string"},
				{Name: "addressCity", Type: "string"},
				{Name: "addressPostcode", Type: "string"},
				{Name: "verifiedOn", Type: "date", Description: "Date the identity was verified with DIA"},
			}},
		{ID: "identity.hpi-practitioner", CategoryID: "identity", Name: "HPI Practitioner Identity (NZ)", Source: schema.SourceCore,
			Description: "Health Practitioner Index (HPI) identity credential for NZ registered health professionals",
			Claims: []schema.ClaimDefinition{
				{Name: "hpiNumber", Type: "string", Required: true, Description: "HPI Person ID (Common Person Number)"},
				{Name: "fhirResourceId", Type: "string", Description: "FHIR Practitioner resource ID from the NZ HPI FHIR API"},
				{Name: "givenNames", Type: "string"},
				{Name: "familyName", Type: "string"},
			}},
		// Derived ZK-style age-over credential — issued by tpt-identity when given a verified DOB VC.
		// The actual DOB is never included; only the binary result is signed.
		{ID: "identity.age-over-proof", CategoryID: "identity", Name: "Age Over Proof", Source: schema.SourceCore,
			Description: "Cryptographically signed assertion that the subject is at least N years old, without revealing the actual date of birth",
			Claims: []schema.ClaimDefinition{
				{Name: "age_over", Type: "number", Required: true, Description: "The minimum age threshold being proved"},
				{Name: "result", Type: "boolean", Required: true, Description: "true if the subject's age >= age_over"},
				{Name: "verifier", Type: "string", Description: "DID of the intended verifier (audience binding)"},
				{Name: "proof_type", Type: "string", Description: "Always 'derived'"},
				{Name: "method", Type: "string", Description: "Computation method: 'issuer-computed'"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
