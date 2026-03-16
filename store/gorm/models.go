package gorm_store

import (
	"time"

	"github.com/LukyNet21/go-auth/models"
)

// userRow is the GORM representation of a user record.
type userRow struct {
	ID              string     `gorm:"column:id;primaryKey"`
	Email           string     `gorm:"column:email;uniqueIndex;not null"`
	Username        string     `gorm:"column:username;not null"`
	EmailVerifiedAt *time.Time `gorm:"column:email_verified_at"`
	CreatedAt       time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt       time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

func (userRow) TableName() string { return "users" }

func (r *userRow) toDomain() *models.User {
	return &models.User{
		ID:              r.ID,
		Email:           r.Email,
		Username:        r.Username,
		EmailVerifiedAt: r.EmailVerifiedAt,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

func userRowFromDomain(u *models.User) *userRow {
	return &userRow{
		ID:              u.ID,
		Email:           u.Email,
		Username:        u.Username,
		EmailVerifiedAt: u.EmailVerifiedAt,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
}

// identityRow is the GORM representation of an identity record.
type identityRow struct {
	ID             string    `gorm:"column:id;primaryKey"`
	UserID         string    `gorm:"column:user_id;index;not null"`
	Provider       string    `gorm:"column:provider;not null"`
	ProviderUserID string    `gorm:"column:provider_user_id;not null"`
	CreatedAt      time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt      time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (identityRow) TableName() string { return "identities" }

func (r *identityRow) toDomain() *models.Identity {
	return &models.Identity{
		ID:             r.ID,
		UserID:         r.UserID,
		Provider:       models.ProviderType(r.Provider),
		ProviderUserID: r.ProviderUserID,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}

func identityRowFromDomain(i *models.Identity) *identityRow {
	return &identityRow{
		ID:             i.ID,
		UserID:         i.UserID,
		Provider:       string(i.Provider),
		ProviderUserID: i.ProviderUserID,
		CreatedAt:      i.CreatedAt,
		UpdatedAt:      i.UpdatedAt,
	}
}

// providerPasswordRow is the GORM representation of a local password record.
type providerPasswordRow struct {
	IdentityID   string    `gorm:"column:identity_id;primaryKey"`
	PasswordHash string    `gorm:"column:password_hash;not null"`
	UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (providerPasswordRow) TableName() string { return "provider_passwords" }

func providerPasswordRowFromDomain(p *models.ProviderPassword) *providerPasswordRow {
	return &providerPasswordRow{
		IdentityID:   p.IdentityID,
		PasswordHash: p.PasswordHash,
		UpdatedAt:    p.UpdatedAt,
	}
}

// refreshTokenRow is the GORM representation of a refresh token record.
type refreshTokenRow struct {
	ID        string    `gorm:"column:id;primaryKey"`
	UserID    string    `gorm:"column:user_id;index;not null"`
	TokenHash string    `gorm:"column:token_hash;uniqueIndex;not null"`
	UserAgent string    `gorm:"column:user_agent"`
	IPAddress string    `gorm:"column:ip_address"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
	Revoked   bool      `gorm:"column:revoked;not null;default:false"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
}

func (refreshTokenRow) TableName() string { return "refresh_tokens" }

func (r *refreshTokenRow) toDomain() *models.RefreshToken {
	return &models.RefreshToken{
		ID:        r.ID,
		UserID:    r.UserID,
		TokenHash: r.TokenHash,
		UserAgent: r.UserAgent,
		IPAddress: r.IPAddress,
		ExpiresAt: r.ExpiresAt,
		Revoked:   r.Revoked,
		CreatedAt: r.CreatedAt,
	}
}

func refreshTokenRowFromDomain(t *models.RefreshToken) *refreshTokenRow {
	return &refreshTokenRow{
		ID:        t.ID,
		UserID:    t.UserID,
		TokenHash: t.TokenHash,
		UserAgent: t.UserAgent,
		IPAddress: t.IPAddress,
		ExpiresAt: t.ExpiresAt,
		Revoked:   t.Revoked,
		CreatedAt: t.CreatedAt,
	}
}
