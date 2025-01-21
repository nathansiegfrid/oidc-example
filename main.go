package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/nathansiegfrid/oidc-example/auth"
)

func main() {
	godotenv.Load()

	authenticator, err := auth.NewAuthenticator(
		auth.OpenIDConnectConfig{
			ClientID:     os.Getenv("OPENID_CONNECT_CLIENT_ID"),
			ClientSecret: os.Getenv("OPENID_CONNECT_CLIENT_SECRET"),
			DiscoveryURL: os.Getenv("OPENID_CONNECT_DISCOVERY_URL"),
			RedirectURL:  os.Getenv("OPENID_CONNECT_REDIRECT_URL"),
		},
		sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET"))),
	)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(-1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		claims, err := authenticator.Authenticate(w, r)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(claims.SubjectID))
	})
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		_, err := authenticator.Authenticate(w, r)
		if err != nil {
			authenticator.BeginAuth(w, r)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
		rawIDToken, err := authenticator.Callback(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := authenticator.Login(w, r, rawIDToken, time.Hour); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		// Note: Use this for front-channel logout.
		if err := authenticator.Logout(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	slog.Info("listening on :4000")
	slog.Error(http.ListenAndServe(":4000", mux).Error())
	os.Exit(-1)
}
