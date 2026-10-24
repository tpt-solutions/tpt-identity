package core

import "github.com/tpt-solutions/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "education",
		Name:        "Education",
		Description: "Academic enrolments, transcripts, and qualifications",
		Icon:        "graduation-cap",
	})

	for _, s := range []schema.Schema{
		{ID: "education.enrolments", CategoryID: "education", Name: "Enrolments", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "institution", Type: "string", Required: true},
				{Name: "programme", Type: "string"},
				{Name: "startDate", Type: "date"},
				{Name: "endDate", Type: "date"},
				{Name: "fullTime", Type: "boolean"},
			}},
		{ID: "education.transcripts", CategoryID: "education", Name: "Academic Transcripts", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "institution", Type: "string", Required: true},
				{Name: "programme", Type: "string", Required: true},
				{Name: "gpa", Type: "number"},
				{Name: "completionDate", Type: "date"},
			}},
		{ID: "education.qualifications", CategoryID: "education", Name: "Academic Qualifications", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "qualification", Type: "string", Required: true},
				{Name: "awardingInstitution", Type: "string", Required: true},
				{Name: "awardDate", Type: "date"},
			}},
		{ID: "education.nzqa", CategoryID: "education", Name: "NZQA Records (NZ)", Source: schema.SourceCore,
			Description: "New Zealand Qualifications Authority records",
			Claims: []schema.ClaimDefinition{
				{Name: "nzqaId", Type: "string", Required: true},
				{Name: "nzqfLevel", Type: "number"},
				{Name: "credits", Type: "number"},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
