package api

import (
	_ "embed"
	"net/http"
)

// openAPISpec is the OpenAPI 3.1 description of the HTTP API. It is served at
// GET /openapi.yaml and checked against the registered routes by openapi_test.go.
//
//go:embed openapi.yaml
var openAPISpec []byte

// handleOpenAPI serves the embedded OpenAPI document.
func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openAPISpec)
}
