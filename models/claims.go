package models

// Claims holds the verified data extracted from an access token.
type Claims struct {
	UserID string
	Email  string
}
