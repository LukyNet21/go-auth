package token

import (
	"errors"
	"time"

	"github.com/LukyNet21/go-auth/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// HMACTokenProvider implements core.TokenProvider using HMAC-SHA256 (HS256).
// For asymmetric signing, see ECDSATokenProvider.
type HMACTokenProvider struct {
	secret         []byte
	accessTokenTTL time.Duration
}

func NewHMACTokenProvider(secret []byte, accessTokenTTL time.Duration) *HMACTokenProvider {
	return &HMACTokenProvider{
		secret:         secret,
		accessTokenTTL: accessTokenTTL,
	}
}

func (p *HMACTokenProvider) GenerateAccessToken(user *models.User) (string, error) {
	now := time.Now()
	claims := jwtClaims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.accessTokenTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.secret)
}

func (p *HMACTokenProvider) ValidateAccessToken(tokenString string) (*models.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return p.secret, nil
	})
	if err != nil {
		return nil, models.ErrTokenExpired
	}

	c, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, models.ErrTokenExpired
	}

	return &models.Claims{
		UserID: c.Subject,
		Email:  c.Email,
	}, nil
}

func (p *HMACTokenProvider) GenerateSecureString(length int) (string, error) {
	return generateSecureString(length)
}
