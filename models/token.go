package models

import "time"

type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string // SHA-256 hex digest of the raw token
	UserAgent string // HTTP User-Agent captured at login, for auditing
	IPAddress string // client IP captured at login, for auditing
	ExpiresAt time.Time
	Revoked   bool // true when explicitly invalidated (logout, password change, etc.)
	CreatedAt time.Time
}

// AuthResult is returned after a successful login.
type AuthResult struct {
	User         *User
	AccessToken  string // short-lived JWT for API requests
	RefreshToken string // raw token for the client (only returned once; hashed in DB)
}
