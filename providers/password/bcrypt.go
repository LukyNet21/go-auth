// providers/password/bcrypt.go
package password

import (
	"golang.org/x/crypto/bcrypt"
)

// BcryptHasher implements the core.PasswordHasher interface.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a new hasher.
// `cost` determines how computationally expensive the hash is (Default is 10).
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

// Hash takes a plaintext password and returns a bcrypt hashed string.
func (h *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Compare checks if the provided plaintext password matches the hashed string.
func (h *BcryptHasher) Compare(hashedPassword, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}
