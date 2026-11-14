package oauth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"wsbridge/internal/ws"
)

const authorizeErrorHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Authorization failed · wsbridge</title>
<style>
:root{color-scheme:light dark;--bg:#f5f6f8;--fg:#1c2024;--muted:#5c6670;--card:#fff;--line:#dfe3e8;--err:#b42318;--errbg:#fef3f2}
@media (prefers-color-scheme:dark){:root{--bg:#14181c;--fg:#e6e9ec;--muted:#9aa4ad;--card:#1d2328;--line:#333c44;--err:#f97066;--errbg:#3a1d1a}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.card{width:100%;max-width:480px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{margin:0 0 8px;font-size:19px}
p{margin:0 0 14px;color:var(--muted);overflow-wrap:anywhere}
code{display:inline-block;padding:1px 6px;border-radius:5px;background:var(--errbg);color:var(--err);font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.note{border-top:1px solid var(--line);padding-top:12px;margin-top:18px;font-size:13px}
</style>
</head>
<body>
<main class="card">
<h1>Authorization could not continue</h1>
<p>{{.Message}}</p>
{{if .Code}}<p><code>{{.Code}}</code></p>{{end}}
<p class="note">No authorization was granted. You may close this page and try again from the client application.</p>
</main>
</body>
</html>
`

// consentWorkspace is a workspace rendered on the consent form.
type consentWorkspace struct {
	Name    string
	Path    string
	MaxPerm ws.Permission
	Checked bool
}

type consentView struct {
	AuthRequestID   string
	CSRFToken       string
	ClientName      string
	RedirectHost    string
	RedirectURI     string
	RequestedScopes []string
	Workspaces      []consentWorkspace
	ErrorMessage    string
	LockedSeconds   int
}

type authorizeErrorView struct {
	Message string
	Code    string
}

func setConsentHeaders(w http.ResponseWriter, status int) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
}

func (s *Server) renderAuthorizeError(w http.ResponseWriter, status int, code, message string) {
	setConsentHeaders(w, status)
	if err := s.error.Execute(w, authorizeErrorView{Message: message, Code: code}); err != nil {
		s.logger.Warn("render authorization error page", "error", err)
	}
}

// lookupClient returns the client and the exact registered redirect URI.
func (s *Server) lookupClient(clientID, redirectURI string) (*ClientRecord, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	c, err := s.store.GetClient(clientID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("unknown client_id")
		}
		s.logger.Error("load registered client", "error", err)
		return nil, fmt.Errorf("client lookup failed")
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("redirect_uri is required")
	}
	for _, registered := range c.RedirectURIs {
		if registered == redirectURI {
			return c, nil
		}
	}
	return nil, fmt.Errorf("redirect_uri does not exactly match a registered redirect URI")
}

type authorizeParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Scope               string
	Resource            string
}

func (s *Server) parseAuthorizeParams(get func(string) string) (authorizeParams, string, string) {
	p := authorizeParams{
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		ResponseType:        get("response_type"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
		State:               get("state"),
		Scope:               get("scope"),
		Resource:            get("resource"),
	}
	if p.ResponseType != "code" {
		return p, "invalid_request", "response_type must be \"code\""
	}
	if !ValidPKCEChallenge(p.CodeChallenge) {
		return p, "invalid_request", "code_challenge must be 43-128 characters of Base64URL"
	}
	if p.CodeChallengeMethod != "S256" {
		return p, "invalid_request", "code_challenge_method must be \"S256\""
	}
	if len(p.State) > 2048 {
		return p, "invalid_request", "state is too long"
	}
	if len(p.Scope) > 512 {
		return p, "invalid_scope", "scope is too long"
	}
	if p.Resource != "" && p.Resource != s.resourceURL {
		return p, "invalid_target", "resource must equal this server's MCP endpoint"
	}
	return p, "", ""
}

func (s *Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.lookupClient(q.Get("client_id"), q.Get("redirect_uri"))
	if err != nil {
		s.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	p, code, message := s.parseAuthorizeParams(q.Get)
	if code != "" {
		s.renderAuthorizeError(w, http.StatusBadRequest, code, message)
		return
	}
	scope := strings.TrimSpace(p.Scope)
	id, err := s.requests.Create(authRequest{
		ClientID:      client.ClientID,
		ClientName:    client.ClientName,
		RedirectURI:   p.RedirectURI,
		CodeChallenge: p.CodeChallenge,
		State:         p.State,
		Resource:      s.resourceURL,
		Scope:         scope,
	})
	if err != nil {
		s.logger.Error("create authorization request", "error", err)
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "failed to start authorization")
		return
	}
	ar, _ := s.requests.Get(id)
	s.renderConsent(w, http.StatusOK, ar, id, "", 0)
}

func (s *Server) renderConsent(w http.ResponseWriter, status int, ar authRequest, id, errMessage string, locked int) {
	scopes := splitScopes(ar.Scope)
	if len(scopes) == 0 {
		scopes = []string{authorizationScope}
	}
	host := ar.RedirectURI
	if u, err := url.Parse(ar.RedirectURI); err == nil && u.Host != "" {
		host = u.Host
	}
	workspaces := make([]consentWorkspace, 0, len(s.workspaces))
	for _, ws := range s.workspaces {
		workspaces = append(workspaces, consentWorkspace{Name: ws.Name, Path: ws.Path, MaxPerm: ws.MaxPerm})
	}
	if locked > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(locked))
	}
	setConsentHeaders(w, status)
	err := s.consent.Execute(w, consentView{
		AuthRequestID:   id,
		CSRFToken:       ar.CSRF,
		ClientName:      ar.ClientName,
		RedirectHost:    host,
		RedirectURI:     ar.RedirectURI,
		RequestedScopes: scopes,
		Workspaces:      workspaces,
		ErrorMessage:    errMessage,
		LockedSeconds:   locked,
	})
	if err != nil {
		s.logger.Warn("render consent page", "error", err)
	}
}

var validGrantTTLs = map[int]bool{1: true, 24: true, 168: true, 720: true}

func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "malformed form submission")
		return
	}
	id := r.PostForm.Get("auth_req_id")
	csrf := r.PostForm.Get("csrf_token")
	ar, ok := s.requests.Get(id)
	if !ok {
		s.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "this authorization request has expired; restart from the client application")
		return
	}
	if subtle.ConstantTimeCompare([]byte(csrf), []byte(ar.CSRF)) != 1 {
		s.renderAuthorizeError(w, http.StatusForbidden, "invalid_request", "the form security token is invalid")
		return
	}

	action := r.PostForm.Get("action")
	switch action {
	case "deny":
		s.requests.Consume(id)
		s.auditEvent("authorize_attempt", map[string]any{
			"status": "denied", "client_id": ar.ClientID, "client_name": ar.ClientName,
		})
		s.redirectToClient(w, ar, url.Values{"error": {"access_denied"}})
		return
	case "approve":
	default:
		s.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", "unrecognized form action")
		return
	}

	if remaining, locked := s.lockout.Locked(); locked {
		s.renderConsent(w, http.StatusTooManyRequests, ar, id, "", remaining)
		return
	}

	passphrase := r.PostForm.Get("passphrase")
	if passphrase == "" {
		s.renderConsent(w, http.StatusOK, ar, id, "Enter the local wsbridge administrator passphrase.", 0)
		return
	}
	adminHash, err := s.store.AdminHash()
	if err != nil {
		s.logger.Error("read administrator passphrase hash", "error", err)
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "failed to verify the administrator passphrase")
		return
	}
	if adminHash == "" {
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "no administrator passphrase is configured; run \"wsbridge passwd\" first")
		return
	}
	valid, err := VerifyAdminPassphrase(adminHash, passphrase)
	if err != nil {
		s.logger.Error("administrator passphrase hash is malformed", "error", err)
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "the administrator passphrase configuration is invalid")
		return
	}
	if !valid {
		s.lockout.Failure()
		if remaining, locked := s.lockout.Locked(); locked {
			s.auditEvent("authorize_attempt", map[string]any{
				"status": "locked", "client_id": ar.ClientID, "client_name": ar.ClientName,
			})
			s.renderConsent(w, http.StatusTooManyRequests, ar, id, "", remaining)
			return
		}
		s.auditEvent("authorize_attempt", map[string]any{
			"status": "bad_passphrase", "client_id": ar.ClientID, "client_name": ar.ClientName,
		})
		s.renderConsent(w, http.StatusOK, ar, id, "Incorrect administrator passphrase.", 0)
		return
	}
	s.lockout.Success()

	client, err := s.lookupClient(ar.ClientID, ar.RedirectURI)
	if err != nil {
		s.renderAuthorizeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	selected, errMessage := s.selectedWorkspaces(r.PostForm["workspaces"])
	perm, err := ws.ParsePermission(strings.TrimSpace(r.PostForm.Get("permission")))
	if errMessage == "" && err != nil {
		errMessage = "Choose a permission level: read, write, or check."
	}
	if errMessage == "" {
		for _, name := range selected {
			for _, ws := range s.workspaces {
				if ws.Name == name && perm > ws.MaxPerm {
					errMessage = fmt.Sprintf("The selected permission %q exceeds the configured max_perm %q for workspace %q.",
						perm, ws.MaxPerm, name)
				}
			}
		}
	}
	ttlHours, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("ttl_hours")))
	if errMessage == "" && (err != nil || !validGrantTTLs[ttlHours]) {
		errMessage = "Choose an authorization lifetime of 1, 24, 168, or 720 hours."
	}
	if errMessage != "" {
		s.renderConsent(w, http.StatusOK, ar, id, errMessage, 0)
		return
	}

	grantID, err := randomID(12)
	if err != nil {
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "failed to create the grant")
		return
	}
	now := s.now()
	grant := &GrantRecord{
		GrantID:    GrantIDPrefix + grantID,
		ClientID:   client.ClientID,
		ClientName: client.ClientName,
		Scopes:     ScopeStrings(splitScopes(ar.Scope)),
		Workspaces: make(map[string]ws.Permission, len(selected)),
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Duration(ttlHours) * time.Hour),
	}
	for _, name := range selected {
		grant.Workspaces[name] = perm
	}
	if err := s.store.CreateGrant(grant); err != nil {
		s.logger.Error("create grant", "error", err)
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "failed to create the grant")
		return
	}
	if err := s.store.ActivateClient(client.ClientID); err != nil {
		s.logger.Error("activate client", "error", err)
	}
	code, err := s.codes.Issue(authCode{
		ClientID:      client.ClientID,
		RedirectURI:   ar.RedirectURI,
		CodeChallenge: ar.CodeChallenge,
		Resource:      ar.Resource,
		GrantID:       grant.GrantID,
	})
	if err != nil {
		s.logger.Error("issue authorization code", "error", err)
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "failed to issue an authorization code")
		return
	}
	s.requests.Consume(id)
	s.auditEvent("authorize_attempt", map[string]any{
		"status": "ok", "grant_id": grant.GrantID, "client_id": client.ClientID,
		"client_name": client.ClientName, "workspaces": selected,
		"permission": perm.String(), "ttl_hours": ttlHours,
	})
	s.redirectToClient(w, ar, url.Values{"code": {code}})
}

// selectedWorkspaces validates the checkbox values against the configured
// workspaces, rejecting unknown names and duplicates.
func (s *Server) selectedWorkspaces(values []string) ([]string, string) {
	if len(values) == 0 {
		return nil, "Select at least one workspace."
	}
	if len(values) > len(s.workspaces) {
		return nil, "The workspace selection is invalid."
	}
	known := make(map[string]bool, len(s.workspaces))
	for _, w := range s.workspaces {
		known[w.Name] = true
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, name := range values {
		if !known[name] || seen[name] {
			return nil, "The workspace selection is invalid."
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, ""
}

// redirectToClient is the only redirect path in the server. It always adds
// the RFC 9207 iss parameter and never redirects to an unvalidated URI.
func (s *Server) redirectToClient(w http.ResponseWriter, ar authRequest, extra url.Values) {
	values := url.Values{"iss": {s.issuer}}
	if ar.State != "" {
		values.Set("state", ar.State)
	}
	for k, vals := range extra {
		values[k] = vals
	}
	location, err := appendOAuthParams(ar.RedirectURI, values)
	if err != nil {
		s.logger.Error("build authorization redirect", "error", err)
		s.renderAuthorizeError(w, http.StatusInternalServerError, "server_error", "failed to build the client redirect")
		return
	}
	s.setNoStore(w)
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}
