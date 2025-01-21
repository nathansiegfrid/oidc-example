package auth

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

func generateRandomString(byteSize int) (string, error) {
	random := make([]byte, byteSize)
	_, err := io.ReadFull(rand.Reader, random)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	})
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, session *sessions.Session) error {
	session.Options.HttpOnly = true
	// Safari rejects "secure" cookies sent without HTTPS.
	session.Options.Secure = r.TLS != nil
	// Firefox and Chrome:
	// Cookie rejected because it has the "SameSite=None" attribute but is missing the "secure" attribute.
	session.Options.SameSite = http.SameSiteDefaultMode
	return session.Save(r, w)
}
