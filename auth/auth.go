package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type OpenIDConnectConfig struct {
	ClientID     string
	ClientSecret string
	DiscoveryURL string
	RedirectURL  string
}

type Authenticator struct {
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
	sessionStore sessions.Store
}

func NewAuthenticator(config OpenIDConnectConfig, sessionStore sessions.Store) (*Authenticator, error) {
	oidcProvider, err := oidc.NewProvider(context.Background(), config.DiscoveryURL)
	if err != nil {
		return nil, err
	}
	// oidc.IDTokenVerifier is used to verify the ID token signature using the OpenID Connect
	// provider's public key.
	oidcVerifier := oidcProvider.Verifier(&oidc.Config{ClientID: config.ClientID})

	// oauth2.Config is used to get the authorization URL and exchange the
	// authorization code for an access token.
	oauth2Config := &oauth2.Config{
		Endpoint:     oidcProvider.Endpoint(),
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &Authenticator{oauth2Config, oidcVerifier, sessionStore}, nil
}

// BeginAuth initiates the OpenID Connect flow by redirecting the user to the
// OpenID Connect provider's authorization endpoint.
//
// The state parameter is used to prevent CSRF attacks. The nonce parameter is
// used to prevent replay attacks. The state and nonce parameters are stored in
// session cookies and validated when the user is redirected back to the
// application.
func (a *Authenticator) BeginAuth(w http.ResponseWriter, r *http.Request) error {
	state, err := generateRandomString(16)
	if err != nil {
		return err
	}
	nonce, err := generateRandomString(16)
	if err != nil {
		return err
	}
	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)
	http.Redirect(w, r, a.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	return nil
}

// Callback validates the state and nonce parameters and exchanges the
// authorization code for an ID token.
func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) (string, error) {
	// Validate the state parameter.
	stateCookie, err := r.Cookie("state")
	if err != nil {
		return "", fmt.Errorf("state cookie not found: %v", err)
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		return "", errors.New("state did not match")
	}

	// Exchange the authorization code for an ID token.
	oauth2Token, err := a.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		return "", fmt.Errorf("failed to exchange token: %v", err)
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no id_token field in oauth2 token")
	}
	idToken, err := a.oidcVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return "", fmt.Errorf("failed to verify ID Token: %v", err)
	}

	// Validate the nonce parameter.
	nonceCookie, err := r.Cookie("nonce")
	if err != nil {
		return "", fmt.Errorf("nonce cookie not found: %v", err)
	}
	if idToken.Nonce != nonceCookie.Value {
		return "", errors.New("nonce did not match")
	}

	return rawIDToken, nil
}

// Login stores the ID token in a session cookie.
// Maybe this can be combined with the Callback function.
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request, rawIDToken string, duration time.Duration) error {
	session, _ := a.sessionStore.Get(r, "SID")
	session.Values["id_token"] = rawIDToken
	session.Options.MaxAge = int(duration.Seconds())
	return setSessionCookie(w, r, session)
}

// Logout clears the session cookie.
func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) error {
	session, _ := a.sessionStore.Get(r, "SID")
	session.Values = make(map[any]any)
	session.Options.MaxAge = -1
	return setSessionCookie(w, r, session)
}

type IDTokenClaims struct {
	SubjectID string `json:"sub"`
	Name      string `json:"name"`
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
	Email     string `json:"email"`
	Verified  bool   `json:"email_verified"`
}

// Authenticate retrieves the raw ID token from the session cookie and verifies it.
func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (IDTokenClaims, error) {
	session, _ := a.sessionStore.Get(r, "SID")
	rawIDToken, _ := session.Values["id_token"].(string)
	if rawIDToken == "" {
		return IDTokenClaims{}, errors.New("no ID token found in session")
	}

	// ID token is verified with the OpenID Connect provider's public key.
	// This public key is retrieved once and cached by the verifier.
	// It will work even if the provider is down.
	idToken, err := a.oidcVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("failed to verify ID token: %v", err)
	}

	// Parse the ID token claims.
	var claims IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return IDTokenClaims{}, fmt.Errorf("failed to parse ID token claims: %v", err)
	}
	return claims, nil
}

// Middleware is an example middleware that authenticates the user and stores
// the user ID in the request context.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := a.Authenticate(w, r)
		if err != nil {
			a.BeginAuth(w, r)
			return
		}

		ctx := WithUserID(r.Context(), claims.SubjectID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
