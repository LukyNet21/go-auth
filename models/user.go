package models

import "time"

type User struct {
	ID              string
	Email           string
	Username        string
	EmailVerifiedAt *time.Time // nil until the user confirms their email address
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
