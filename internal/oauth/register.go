package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type registerRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
}

type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
}

const maxClientNameLen = 200

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be a JSON object")
		return
	}
	// Reject trailing JSON values.
	if dec.More() {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must contain exactly one JSON object")
		return
	}

	if n := len(req.RedirectURIs); n == 0 || n > MaxRedirectURIs {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri",
			fmt.Sprintf("redirect_uris must contain 1-%d entries", MaxRedirectURIs))
		return
	}
	seen := make(map[string]bool, len(req.RedirectURIs))
	uris := make([]string, 0, len(req.RedirectURIs))
	for _, raw := range req.RedirectURIs {
		if err := ValidateRedirectURI(raw, s.redirects); err != nil {
			// The rejected URI is configuration input, not a secret; the spec
			// requires logging it in full so the operator can allow it.
			s.logger.Warn("rejected redirect_uri during registration", "redirect_uri", raw, "error", err)
			s.auditEvent("dcr_register", map[string]any{
				"status": "rejected", "reason": "invalid_redirect_uri", "redirect_uri": raw,
			})
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is not allowed")
			return
		}
		if !seen[raw] {
			seen[raw] = true
			uris = append(uris, raw)
		}
	}

	authMethod := strings.TrimSpace(req.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
			"token_endpoint_auth_method must be \"none\"")
		return
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	for _, gt := range grantTypes {
		switch gt {
		case "authorization_code", "refresh_token":
		default:
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
				"unsupported grant_type")
			return
		}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, rt := range responseTypes {
		if rt != "code" {
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
				"unsupported response_type")
			return
		}
	}

	appType := strings.TrimSpace(req.ApplicationType)
	if appType == "" {
		appType = "web"
	}
	if appType != "web" && appType != "native" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
			"application_type must be \"web\" or \"native\"")
		return
	}

	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "Unnamed client"
	}
	if len(name) > maxClientNameLen {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
			fmt.Sprintf("client_name must be at most %d bytes", maxClientNameLen))
		return
	}

	idSuffix, err := randomID(6)
	if err != nil {
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to allocate client id")
		return
	}
	now := s.now()
	client := &ClientRecord{
		ClientID:                ClientIDPrefix + idSuffix,
		ClientName:              name,
		RedirectURIs:            uris,
		ApplicationType:         appType,
		GrantTypes:              append([]string(nil), grantTypes...),
		ResponseTypes:           append([]string(nil), responseTypes...),
		TokenEndpointAuthMethod: authMethod,
		CreatedAt:               now,
	}
	if err := s.store.RegisterClient(client); err != nil {
		if errors.Is(err, ErrClientLimit) {
			s.auditEvent("dcr_register", map[string]any{"status": "rejected", "reason": "client_limit"})
			s.writeOAuthError(w, http.StatusTooManyRequests, "invalid_client_metadata",
				"client registration limit reached")
			return
		}
		s.logger.Error("register client failed", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to register client")
		return
	}

	s.auditEvent("dcr_register", map[string]any{
		"status":      "ok",
		"client_id":   client.ClientID,
		"client_name": client.ClientName,
		"redirects":   uris,
	})
	s.writeJSON(w, http.StatusCreated, registerResponse{
		ClientID:                client.ClientID,
		ClientIDIssuedAt:        now.Unix(),
		ClientName:              client.ClientName,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		ApplicationType:         client.ApplicationType,
	})
}
