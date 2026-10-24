// Te Whatu Ora (Health New Zealand) SMART on FHIR bridge.
//
// Registration: https://www.tewhatuora.govt.nz/health-services-and-programmes/digital-health/
// UAT endpoints: https://api.hip-uat.digital.health.nz/fhir/
// NZ FHIR IG:   https://build.fhir.org/ig/HL7NZ/nzbase/

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
)

// NZ FHIR identifier system URIs from the NZ Base FHIR IG.
const (
	// NHI (National Health Index) — patient identifier.
	nhiSystemURI = "https://standards.digital.health.nz/ns/nhi-id"
	// HPI (Health Practitioner Index) — practitioner person identifier.
	hpiPersonSystemURI = "https://standards.digital.health.nz/ns/hpi-person-id"
	// HPI CPN (Common Person Number) — same person, alternative system URI in some responses.
	hpiCPNSystemURI = "https://standards.digital.health.nz/ns/hpi-person-cpn"
)

// TeWhatuOraConfig configures the Te Whatu Ora SMART on FHIR bridge.
type TeWhatuOraConfig struct {
	// SMART on FHIR authorization server endpoints.
	// Refer to the HIP (Health Identity Platform) developer documentation for current URLs.
	// UAT example:  https://auth.hip-uat.digital.health.nz/auth/oauth2/authorize
	AuthEndpoint  string
	TokenEndpoint string

	// FHIRBase is the base URL of the FHIR resource server.
	// UAT NHI:  https://api.hip-uat.digital.health.nz/fhir/nhi/v1
	// UAT HPI:  https://api.hip-uat.digital.health.nz/fhir/hpi/v1
	FHIRBase string

	// OAuth2 client credentials registered with Te Whatu Ora / HIP.
	ClientID        string
	ClientSecret    string
	RedirectBaseURL string

	// ResourceType is "Patient" (default, uses NHI) or "Practitioner" (uses HPI).
	ResourceType string
}

// TeWhatuOraBridge authenticates NZ patients and health practitioners via
// Te Whatu Ora SMART on FHIR. After authorization code exchange it fetches
// the FHIR Patient or Practitioner resource to obtain the NHI or HPI number,
// which becomes the stable ExternalID used for DID linking.
type TeWhatuOraBridge struct {
	cfg TeWhatuOraConfig
}

// NewTeWhatuOra creates a Te Whatu Ora bridge. ResourceType defaults to "Patient".
func NewTeWhatuOra(cfg TeWhatuOraConfig) (*TeWhatuOraBridge, error) {
	if cfg.AuthEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, errors.New("te-whatu-ora: AuthEndpoint and TokenEndpoint are required")
	}
	if cfg.FHIRBase == "" {
		return nil, errors.New("te-whatu-ora: FHIRBase is required")
	}
	if cfg.ResourceType == "" {
		cfg.ResourceType = "Patient"
	}
	if cfg.ResourceType != "Patient" && cfg.ResourceType != "Practitioner" {
		return nil, fmt.Errorf("te-whatu-ora: ResourceType must be Patient or Practitioner, got %q", cfg.ResourceType)
	}
	return &TeWhatuOraBridge{cfg: cfg}, nil
}

func (b *TeWhatuOraBridge) Name() string { return "te-whatu-ora" }

func (b *TeWhatuOraBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("te-whatu-ora: use RedirectBridge methods (AuthorizationURL / ExchangeCode)")
}

// AuthorizationURL returns the SMART on FHIR authorization redirect URL.
// Scopes follow the SMART on FHIR App Launch specification (HL7).
func (b *TeWhatuOraBridge) AuthorizationURL(ctx context.Context, state string) (string, error) {
	scopes := b.smartScopes()
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {b.cfg.ClientID},
		"redirect_uri":  {b.callbackURL()},
		"scope":         {scopes},
		"state":         {state},
		// SMART on FHIR requires the aud parameter to identify the resource server.
		"aud": {b.cfg.FHIRBase},
	}
	return b.cfg.AuthEndpoint + "?" + params.Encode(), nil
}

// ExchangeCode exchanges the authorization code, fetches the FHIR resource to
// obtain the NHI/HPI number, and returns the normalized ExternalIdentity.
func (b *TeWhatuOraBridge) ExchangeCode(ctx context.Context, code string) (*bridge.ExternalIdentity, error) {
	resp, err := http.PostForm(b.cfg.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {b.callbackURL()},
		"client_id":     {b.cfg.ClientID},
		"client_secret": {b.cfg.ClientSecret},
	})
	if err != nil {
		return nil, fmt.Errorf("te-whatu-ora: token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("te-whatu-ora: token endpoint returned HTTP %d", resp.StatusCode)
	}

	// SMART on FHIR token response carries extra context claims.
	var tok struct {
		AccessToken string `json:"access_token"`
		// patient is the FHIR Patient resource ID (present for patient-level scopes).
		Patient  string `json:"patient"`
		// fhirUser is the full FHIR resource URL for the authenticated user, e.g. "Patient/ZCX7823".
		FHIRUser string `json:"fhirUser"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("te-whatu-ora: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("te-whatu-ora: no access_token in response")
	}

	// Determine the FHIR resource ID from the token context claims.
	resourceID := tok.Patient
	if resourceID == "" && tok.FHIRUser != "" {
		// "Patient/abc123" → "abc123"
		if parts := strings.SplitN(tok.FHIRUser, "/", 2); len(parts) == 2 {
			resourceID = parts[1]
		} else {
			resourceID = tok.FHIRUser
		}
	}
	if resourceID == "" {
		return nil, errors.New("te-whatu-ora: no patient/fhirUser context in token response")
	}

	return b.fetchFHIRIdentity(ctx, tok.AccessToken, resourceID)
}

func (b *TeWhatuOraBridge) fetchFHIRIdentity(ctx context.Context, accessToken, resourceID string) (*bridge.ExternalIdentity, error) {
	fhirURL := strings.TrimRight(b.cfg.FHIRBase, "/") + "/" + b.cfg.ResourceType + "/" + resourceID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fhirURL, nil)
	if err != nil {
		return nil, fmt.Errorf("te-whatu-ora: build FHIR request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/fhir+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("te-whatu-ora: fetch FHIR resource: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("te-whatu-ora: FHIR resource returned HTTP %d", resp.StatusCode)
	}

	var resource fhirPatientResource
	if err := json.NewDecoder(resp.Body).Decode(&resource); err != nil {
		return nil, fmt.Errorf("te-whatu-ora: decode FHIR resource: %w", err)
	}

	// Extract NHI (patient) or HPI (practitioner) from the identifier array.
	nhi, hpi := "", ""
	for _, id := range resource.Identifier {
		switch id.System {
		case nhiSystemURI:
			nhi = id.Value
		case hpiPersonSystemURI, hpiCPNSystemURI:
			if hpi == "" {
				hpi = id.Value
			}
		}
	}

	// Choose the stable external ID: NHI preferred for patients, HPI for practitioners,
	// FHIR resource ID as last resort.
	externalID, idType := resourceID, "fhir-id"
	if nhi != "" {
		externalID, idType = nhi, "nhi"
	} else if hpi != "" {
		externalID, idType = hpi, "hpi"
	}

	claims := map[string]string{
		"fhir_resource_id":   resourceID,
		"fhir_resource_type": b.cfg.ResourceType,
		"id_type":            idType,
	}
	if nhi != "" {
		claims["nhi_number"] = nhi
	}
	if hpi != "" {
		claims["hpi_number"] = hpi
	}
	// Extract name and birth date for downstream credential issuance.
	if len(resource.Name) > 0 {
		n := resource.Name[0]
		if n.Family != "" {
			claims["family_name"] = n.Family
		}
		for _, g := range n.Given {
			if g != "" {
				claims["given_name"] = g
				break
			}
		}
	}
	if resource.BirthDate != "" {
		claims["dob"] = resource.BirthDate
	}

	return &bridge.ExternalIdentity{
		Provider:   "te-whatu-ora",
		ExternalID: externalID,
		Claims:     claims,
	}, nil
}

func (b *TeWhatuOraBridge) callbackURL() string {
	return strings.TrimRight(b.cfg.RedirectBaseURL, "/") + "/auth/te-whatu-ora/callback"
}

func (b *TeWhatuOraBridge) smartScopes() string {
	// SMART on FHIR App Launch scopes.
	if b.cfg.ResourceType == "Patient" {
		return "openid fhirUser launch/patient patient/*.read"
	}
	// Practitioner scope for HPI (health professional identity).
	return "openid fhirUser user/Practitioner.read"
}

// fhirPatientResource holds the FHIR Patient/Practitioner fields we read.
// We only deserialize the fields needed for identity extraction.
type fhirPatientResource struct {
	ResourceType string              `json:"resourceType"`
	ID           string              `json:"id"`
	Identifier   []fhirIdentifierEnt `json:"identifier"`
	Name         []fhirHumanNameEnt  `json:"name"`
	BirthDate    string              `json:"birthDate"`
}

type fhirIdentifierEnt struct {
	System string `json:"system"`
	Value  string `json:"value"`
}

type fhirHumanNameEnt struct {
	Family string   `json:"family"`
	Given  []string `json:"given"`
}
