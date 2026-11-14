package oauth

import "net/http"

type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

type authorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		// Query parameters are ignored by RFC 9728, not an error.
		_ = r.URL.Query()
	}
	s.writeJSON(w, http.StatusOK, protectedResourceMetadata{
		Resource:               s.resourceURL,
		AuthorizationServers:   []string{s.issuer},
		ScopesSupported:        []string{authorizationScope, offlineAccessScope},
		BearerMethodsSupported: []string{"header"},
	})
}

func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, authorizationServerMetadata{
		Issuer:                                     s.issuer,
		AuthorizationEndpoint:                      s.issuer + "/oauth/authorize",
		TokenEndpoint:                              s.issuer + "/oauth/token",
		RegistrationEndpoint:                       s.issuer + "/oauth/register",
		RevocationEndpoint:                         s.issuer + "/oauth/revoke",
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		TokenEndpointAuthMethodsSupported:          []string{"none"},
		RevocationEndpointAuthMethodsSupported:     []string{"none"},
		ScopesSupported:                            []string{authorizationScope, offlineAccessScope},
		AuthorizationResponseIssParameterSupported: true,
		ClientIDMetadataDocumentSupported:          false,
	})
}
