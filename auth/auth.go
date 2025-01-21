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

type IDTokenClaims struct {
	SubjectID string `json:"sub"`
	Name      string `json:"name"`
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
	Email     string `json:"email"`
	Verified  bool   `json:"email_verified"`
}

type OpenIDConnectConfig struct {
	ClientID     string
	ClientSecret string
	DiscoveryURL string
	RedirectURL  string
}

type Authenticator struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
	store    sessions.Store
}

func NewAuthenticator(config OpenIDConnectConfig, sessionStore sessions.Store) (*Authenticator, error) {
	provider, err := oidc.NewProvider(context.Background(), config.DiscoveryURL)
	if err != nil {
		return nil, err
	}
	oauth2Config := &oauth2.Config{
		Endpoint:     provider.Endpoint(),
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	return &Authenticator{oauth2Config, verifier, sessionStore}, nil
}

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

func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (IDTokenClaims, error) {
	session, _ := a.store.Get(r, "SID")
	rawIDToken, _ := session.Values["id_token"].(string)
	if rawIDToken == "" {
		return IDTokenClaims{}, errors.New("no ID token found in session")
	}
	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("failed to verify ID token: %v", err)
	}
	var claims IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return IDTokenClaims{}, fmt.Errorf("failed to parse ID token claims: %v", err)
	}
	return claims, nil
}

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
	http.Redirect(w, r, a.config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	return nil
}

func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) (string, error) {
	stateCookie, err := r.Cookie("state")
	if err != nil {
		return "", fmt.Errorf("state cookie not found: %v", err)
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		return "", errors.New("state did not match")
	}

	oauth2Token, err := a.config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		return "", fmt.Errorf("failed to exchange token: %v", err)
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no id_token field in oauth2 token")
	}
	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return "", fmt.Errorf("failed to verify ID Token: %v", err)
	}

	nonceCookie, err := r.Cookie("nonce")
	if err != nil {
		return "", fmt.Errorf("nonce cookie not found: %v", err)
	}
	if idToken.Nonce != nonceCookie.Value {
		return "", errors.New("nonce did not match")
	}

	return rawIDToken, nil
}

func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request, rawIDToken string, duration time.Duration) error {
	session, _ := a.store.Get(r, "SID")
	session.Values["id_token"] = rawIDToken
	session.Options.MaxAge = int(duration.Seconds())
	return setSessionCookie(w, r, session)
}

func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) error {
	session, _ := a.store.Get(r, "SID")
	session.Values = make(map[any]any)
	session.Options.MaxAge = -1
	return setSessionCookie(w, r, session)
}
