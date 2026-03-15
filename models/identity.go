package models

import "time"

type ProviderType string

const (
	ProviderLocal  ProviderType = "local"
	ProviderGoogle ProviderType = "google"
	ProviderGithub ProviderType = "github"
)

type Identity struct {
	ID             string
	UserID         string
	Provider       ProviderType // which auth provider issued this identity
	ProviderUserID string       // the user's ID within that provider (email for local, sub for OAuth)
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
