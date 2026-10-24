package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "healthcare",
		Name:        "Healthcare",
		Description: "Medical records, clinical history, and health credentials",
		Icon:        "heart-pulse",
	})

	for _, s := range []schema.Schema{
		{ID: "healthcare.gp-records", CategoryID: "healthcare", Name: "GP / Primary Care Records", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "practiceId", Type: "string", Required: true},
				{Name: "practiceName", Type: "string"},
				{Name: "enrolledSince", Type: "date"},
			}},
		{ID: "healthcare.specialist", CategoryID: "healthcare", Name: "Specialist Visits", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "specialty", Type: "string", Required: true},
				{Name: "providerName", Type: "string"},
				{Name: "visitDate", Type: "date"},
			}},
		{ID: "healthcare.pharmacy", CategoryID: "healthcare", Name: "Pharmacy / Dispensing Records", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "pharmacyId", Type: "string"},
				{Name: "pharmacyName", Type: "string"},
			}},
		{ID: "healthcare.allergies", CategoryID: "healthcare", Name: "Allergies & Adverse Reactions", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "allergen", Type: "string", Required: true},
				{Name: "reactionType", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "recordedDate", Type: "date"},
			}},
		{ID: "healthcare.immunisation", CategoryID: "healthcare", Name: "Immunisation History", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "vaccine", Type: "string", Required: true},
				{Name: "administeredDate", Type: "date", Required: true},
				{Name: "batchNumber", Type: "string"},
				{Name: "administeringProvider", Type: "string"},
			}},
		{ID: "healthcare.radiology", CategoryID: "healthcare", Name: "Radiology / Imaging", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "modality", Type: "string", Required: true, Description: "e.g. X-ray, MRI, CT"},
				{Name: "bodyPart", Type: "string"},
				{Name: "studyDate", Type: "date"},
				{Name: "reportingRadiologist", Type: "string"},
			}},
		{ID: "healthcare.pathology", CategoryID: "healthcare", Name: "Pathology / Lab Results", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "testName", Type: "string", Required: true},
				{Name: "collectionDate", Type: "date"},
				{Name: "laboratory", Type: "string"},
			}},
		{ID: "healthcare.dental", CategoryID: "healthcare", Name: "Dental Records", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "practiceId", Type: "string"},
				{Name: "practiceName", Type: "string"},
			}},
		{ID: "healthcare.acc-injury", CategoryID: "healthcare", Name: "ACC Injury Records (NZ)", Source: schema.SourceCore,
			Description: "Accident Compensation Corporation injury claims",
			Claims: []schema.ClaimDefinition{
				{Name: "accClaimNumber", Type: "string", Required: true},
				{Name: "injuryDate", Type: "date"},
				{Name: "injuryType", Type: "string"},
				{Name: "status", Type: "string"},
			}},
		{ID: "healthcare.acc-authorisation", CategoryID: "healthcare", Name: "ACC Treatment Authorisation (NZ)", Source: schema.SourceCore,
			Description: "Accident Compensation Corporation authorisation for a specific treatment or service",
			Claims: []schema.ClaimDefinition{
				{Name: "accClaimNumber", Type: "string", Required: true},
				{Name: "authorisationNumber", Type: "string", Required: true},
				{Name: "serviceType", Type: "string", Required: true, Description: "Authorised service, e.g. physiotherapy, specialist consultation"},
				{Name: "provider", Type: "string", Description: "Authorised healthcare provider name or HPI number"},
				{Name: "maxSessions", Type: "string", Description: "Maximum number of authorised sessions"},
				{Name: "validFrom", Type: "date"},
				{Name: "validUntil", Type: "date"},
				{Name: "status", Type: "string", Description: "active, expired, or cancelled"},
			}},
		{ID: "healthcare.nhi-patient", CategoryID: "healthcare", Name: "NHI Patient Record (NZ)", Source: schema.SourceCore,
			Description: "National Health Index patient identity credential linking DID to FHIR Patient resource",
			Claims: []schema.ClaimDefinition{
				{Name: "nhiNumber", Type: "string", Required: true, Description: "NHI number, e.g. ZCX7823"},
				{Name: "fhirResourceId", Type: "string", Description: "FHIR Patient resource ID from the NZ NHI FHIR API"},
				{Name: "givenNames", Type: "string"},
				{Name: "familyName", Type: "string"},
				{Name: "dateOfBirth", Type: "date"},
			}},
		{ID: "healthcare.disability", CategoryID: "healthcare", Name: "Disability Assessments", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "assessmentType", Type: "string"},
				{Name: "assessmentDate", Type: "date"},
				{Name: "fundingAuthority", Type: "string"},
			}},
		// Extra-sensitive: require individual explicit consent even under a category grant.
		{ID: "healthcare.mental-health", CategoryID: "healthcare", Name: "Mental Health Records", Source: schema.SourceCore,
			ExtraSensitive: true,
			Claims: []schema.ClaimDefinition{
				{Name: "providerName", Type: "string"},
				{Name: "serviceType", Type: "string"},
			}},
		{ID: "healthcare.sexual-health", CategoryID: "healthcare", Name: "Sexual Health Records", Source: schema.SourceCore,
			ExtraSensitive: true},
		{ID: "healthcare.reproductive-health", CategoryID: "healthcare", Name: "Reproductive Health Records", Source: schema.SourceCore,
			ExtraSensitive: true},
		{ID: "healthcare.addiction", CategoryID: "healthcare", Name: "Addiction & Substance Use", Source: schema.SourceCore,
			ExtraSensitive: true,
			Claims: []schema.ClaimDefinition{
				{Name: "programmeType", Type: "string"},
				{Name: "providerName", Type: "string"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
