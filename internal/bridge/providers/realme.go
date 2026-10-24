//go:build saml

// RealMe bridge requires: go get github.com/crewjam/saml
// Build with: go build -tags saml ./...
//
// Registration: apply for SP access at https://www.realme.govt.nz/realme-businesses/
// UAT IDP metadata: https://mts.realme.govt.nz/realme-mts/metadata/idp
// Production IDP metadata: contact DIA (Department of Internal Affairs)

package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	crewsaml "github.com/crewjam/saml"
)

// RealMeTier represents the assurance tier of a RealMe integration.
type RealMeTier string

const (
	// RealMeLogin is the basic tier (LOA1): pseudonymous login, no verified personal data.
	RealMeLogin RealMeTier = "login"
	// RealMeVerified is the higher-assurance tier (LOA2): verified full name, DoB, address.
	RealMeVerified RealMeTier = "verified"
)

// RealMe SAML attribute URN prefix.
const realmeAttrPrefix = "urn:nz:govt:dia:realme:identity:attribute:"

// RealMe Level of Assurance URN values.
const (
	realmeLOA1 = "urn:nzl:govt:ict:stds:auth:as:1.0:idassurance:loa1"
	realmeLOA2 = "urn:nzl:govt:ict:stds:auth:as:1.0:idassurance:loa2"
	realmeLOA3 = "urn:nzl:govt:ict:stds:auth:as:1.0:idassurance:loa3"
)

// RealMeConfig configures the RealMe SAML SP.
type RealMeConfig struct {
	// Tier controls whether to use RealMe Login (LOA1) or RealMe Verified (LOA2+).
	Tier RealMeTier
	// IDPMetadataURL is the RealMe IdP metadata URL.
	// UAT:        https://mts.realme.govt.nz/realme-mts/metadata/idp
	// Production: supplied by DIA after SP registration.
	IDPMetadataURL string
	// EntityID is this SP's entity ID registered with DIA.
	EntityID string
	// ACSPath is the Assertion Consumer Service path, e.g. "/auth/realme/acs".
	ACSPath string
	// MetadataPath is the SP metadata path, e.g. "/auth/realme/metadata".
	// Defaults to ACSPath with "/acs" → "/metadata".
	MetadataPath string
	// CertFile and KeyFile are the SP's RSA signing certificate and private key (PEM).
	// Generate with: openssl req -x509 -newkey rsa:2048 -keyout sp.key -out sp.crt -days 3650 -nodes
	CertFile string
	KeyFile  string
}

// RealMeBridge authenticates NZ users via RealMe (Department of Internal Affairs SAML IdP).
// The stable external identifier is the FLT (Federated Login Token) — a pseudonymous,
// per-service identifier issued by RealMe in the SAML assertion NameID.
type RealMeBridge struct {
	base *SAMLBridge
	tier RealMeTier
}

// NewRealMe creates and initialises a RealMe bridge, fetching IdP metadata via ctx.
func NewRealMe(ctx context.Context, cfg RealMeConfig) (*RealMeBridge, error) {
	if cfg.Tier == "" {
		cfg.Tier = RealMeLogin
	}
	base, err := NewSAML(ctx, SAMLConfig{
		Name:           "realme",
		IDPMetadataURL: cfg.IDPMetadataURL,
		EntityID:       cfg.EntityID,
		ACSPath:        cfg.ACSPath,
		MetadataPath:   cfg.MetadataPath,
		CertFile:       cfg.CertFile,
		KeyFile:        cfg.KeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("realme: %w", err)
	}
	return &RealMeBridge{base: base, tier: cfg.Tier}, nil
}

func (b *RealMeBridge) Name() string { return "realme" }

func (b *RealMeBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("realme: use SAMLBridgeHandler.ProcessACS for RealMe authentication")
}

// MetadataHandler serves the SP's SAML metadata XML (implements SAMLBridgeHandler).
func (b *RealMeBridge) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	b.base.MetadataHandler(w, r)
}

// PrepareAuth generates a RealMe AuthnRequest (implements SAMLBridgeHandler).
func (b *RealMeBridge) PrepareAuth(ctx context.Context) (string, string, error) {
	return b.base.PrepareAuth(ctx)
}

// ProcessACS validates the RealMe SAMLResponse and maps RealMe attributes
// (implements SAMLBridgeHandler).
func (b *RealMeBridge) ProcessACS(r *http.Request, requestIDs []string) (*bridge.ExternalIdentity, error) {
	assertion, err := b.base.parseResponse(r, requestIDs)
	if err != nil {
		return nil, fmt.Errorf("realme: parse SAML response: %w", err)
	}
	return b.mapRealMeIdentity(assertion)
}

func (b *RealMeBridge) mapRealMeIdentity(assertion *crewsaml.Assertion) (*bridge.ExternalIdentity, error) {
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return nil, errors.New("realme: missing NameID (FLT) in assertion")
	}
	flt := assertion.Subject.NameID.Value
	if flt == "" {
		return nil, errors.New("realme: empty FLT in NameID")
	}

	// The FLT is a pseudonymous, per-service stable identifier — safe to use as ExternalID.
	claims := map[string]string{
		"flt": flt,
	}

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) == 0 {
				continue
			}
			v := attr.Values[0].Value
			// Strip the RealMe attribute URN prefix for the switch.
			key := strings.TrimPrefix(attr.Name, realmeAttrPrefix)
			switch key {
			case "familyName":
				claims["family_name"] = v
			case "givenNames":
				claims["given_name"] = v
			case "dateOfBirth":
				claims["dob"] = v // ISO 8601, e.g. "1985-03-14"
			case "residenceAddressLine1":
				claims["address_line1"] = v
			case "residenceAddressLine2":
				claims["address_line2"] = v
			case "residenceCity":
				claims["address_city"] = v
			case "residencePostCode":
				claims["address_postcode"] = v
			case "residenceCountry":
				claims["address_country"] = v
			case "verifiedOn":
				claims["verified_on"] = v // date identity was verified with DIA
			case "loaAchieved":
				claims["loa"] = v
				claims["loa_level"] = loaLevel(v)
			}
		}
	}

	// Enforce tier: RealMeVerified requires at least LOA2.
	if b.tier == RealMeVerified {
		if loa, ok := claims["loa"]; !ok || (loa != realmeLOA2 && loa != realmeLOA3) {
			return nil, fmt.Errorf("realme: LOA2+ required for verified tier, got %q", claims["loa"])
		}
	}

	return &bridge.ExternalIdentity{
		Provider:   "realme",
		ExternalID: flt,
		Claims:     claims,
	}, nil
}

// loaLevel converts a RealMe LOA URN to a short level string ("1", "2", "3").
func loaLevel(loaURN string) string {
	switch loaURN {
	case realmeLOA1:
		return "1"
	case realmeLOA2:
		return "2"
	case realmeLOA3:
		return "3"
	default:
		return "unknown"
	}
}
