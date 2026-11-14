package oauth

import (
	"errors"
	"net/http"
	"strings"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form submission")
		return
	}
	grantType := r.PostForm.Get("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCode(w, r)
	case "refresh_token":
		s.handleRefreshToken(w, r)
	case "":
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	if code == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	rec, ok := s.codes.Take(code)
	if !ok {
		if used, replay := s.codes.Used(code); replay {
			if _, err := s.store.RevokeGrant(used.GrantID); err != nil {
				s.logger.Error("revoke grant after authorization code replay", "error", err)
			}
			s.auditEvent("token_replay_revoked", map[string]any{
				"grant_id": used.GrantID, "client_id": used.ClientID, "kind": "authorization_code",
			})
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code replay detected")
			return
		}
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}

	if r.PostForm.Get("client_id") != rec.ClientID {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id does not match the authorization code")
		return
	}
	if r.PostForm.Get("redirect_uri") != rec.RedirectURI {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if resource := r.PostForm.Get("resource"); resource != "" && resource != s.resourceURL {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not match this server")
		return
	}
	if !VerifyPKCE(r.PostForm.Get("code_verifier"), rec.CodeChallenge) {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	pair, err := s.store.IssueTokens(rec.GrantID, rec.ClientID, s.resourceURL)
	if err != nil {
		if errors.Is(err, ErrInvalidGrant) {
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the grant is no longer active")
			return
		}
		s.logger.Error("issue tokens", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}
	scope := s.grantScope(pair.GrantID)
	s.auditEvent("token_issue", map[string]any{
		"grant_id": pair.GrantID, "client_id": pair.ClientID, "grant_type": "authorization_code",
	})
	s.writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    pair.ExpiresIn,
		RefreshToken: pair.RefreshToken,
		Scope:        scope,
	})
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refresh := r.PostForm.Get("refresh_token")
	if refresh == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	if resource := r.PostForm.Get("resource"); resource != "" && resource != s.resourceURL {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not match this server")
		return
	}
	clientID := r.PostForm.Get("client_id")
	pair, err := s.store.RotateRefresh(refresh, clientID, s.resourceURL)
	if err != nil {
		var replay *ReplayError
		switch {
		case errors.As(err, &replay):
			s.auditEvent("token_replay_revoked", map[string]any{
				"grant_id": replay.GrantID, "client_id": clientID, "kind": "refresh_token",
			})
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token replay detected")
		case errors.Is(err, ErrResourceTarget):
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not match this server")
		case errors.Is(err, ErrInvalidGrant), errors.Is(err, ErrNotFound):
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired, or revoked")
		default:
			s.logger.Error("rotate refresh token", "error", err)
			s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to rotate tokens")
		}
		return
	}
	s.auditEvent("token_refresh", map[string]any{
		"grant_id": pair.GrantID, "client_id": pair.ClientID,
	})
	s.writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    pair.ExpiresIn,
		RefreshToken: pair.RefreshToken,
		Scope:        s.grantScope(pair.GrantID),
	})
}

func (s *Server) grantScope(grantID string) string {
	g, err := s.store.GetGrant(grantID)
	if err != nil || len(g.Scopes) == 0 {
		return strings.Join(ScopeStrings(nil), " ")
	}
	return strings.Join(g.Scopes, " ")
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form submission")
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	grantID, found, err := s.store.RevokeTokenByValue(token)
	if err != nil {
		s.logger.Error("revoke token", "error", err)
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to revoke token")
		return
	}
	if found {
		s.auditEvent("grant_revoke", map[string]any{
			"grant_id": grantID, "reason": "rfc7009",
		})
	}
	// RFC 7009: unknown or already-expired tokens still succeed.
	s.setNoStore(w)
	w.WriteHeader(http.StatusOK)
}
