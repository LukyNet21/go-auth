package token

import (
	"crypto/ecdsa"
	"errors"
	"time"

	"github.com/LukyNet21/go-auth/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ECDSATokenProvider implements core.TokenProvider using ECDSA (ES256).
// Pass an *ecdsa.PrivateKey - the public key is derived from it for validation.
// For shared-secret signing, see HMACTokenProvider.
type ECDSATokenProvider struct {
	privateKey     *ecdsa.PrivateKey
	accessTokenTTL time.Duration
}

func NewECDSATokenProvider(privateKey *ecdsa.PrivateKey, accessTokenTTL time.Duration) *ECDSATokenProvider {
	return &ECDSATokenProvider{
		privateKey:     privateKey,
		accessTokenTTL: accessTokenTTL,
	}
}

func (p *ECDSATokenProvider) GenerateAccessToken(user *models.User) (string, error) {
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

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(p.privateKey)
}

func (p *ECDSATokenProvider) ValidateAccessToken(tokenString string) (*models.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return &p.privateKey.PublicKey, nil
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

func (p *ECDSATokenProvider) GenerateSecureString(length int) (string, error) {
	return generateSecureString(length)
}
