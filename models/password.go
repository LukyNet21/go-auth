package models

import "time"

type ProviderPassword struct {
	IdentityID   string
	PasswordHash string
	UpdatedAt    time.Time
}
