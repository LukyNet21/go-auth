package token

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
)

type jwtClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func generateSecureString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
