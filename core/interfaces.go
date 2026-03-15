package core

import (
	"context"

	"github.com/LukyNet21/go-auth/models"
)

// Store defines the database operations required by the Auth Service.
type Store interface {
	// Reads
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetLocalIdentityByUserID(ctx context.Context, userID string) (*models.Identity, error)
	GetPasswordHash(ctx context.Context, identityID string) (string, error)

	// Writes
	CreateUserWithLocalIdentity(ctx context.Context, user *models.User, identity *models.Identity, password *models.ProviderPassword) error
	UpdatePasswordHash(ctx context.Context, identityID, newHash string) error

	// Sessions
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenID string) (*models.RefreshToken, error)
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllRefreshTokensByUserID(ctx context.Context, userID string) error
}

// PasswordHasher abstracts the hashing algorithm.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hashedPassword, plainPassword string) error
}

// TokenProvider handles generating secure strings and JWTs.
type TokenProvider interface {
	// GenerateAccessToken creates the short-lived JWT for API access.
	GenerateAccessToken(user *models.User) (string, error)

	// GenerateSecureString creates a cryptographically secure random string.
	GenerateSecureString(length int) (string, error)

	// ValidateAccessToken validates the authenticity and expiration of an access token
	// and returns the embedded claims.
	ValidateAccessToken(token string) (*models.Claims, error)
}

// Mailer abstracts email sending.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}
