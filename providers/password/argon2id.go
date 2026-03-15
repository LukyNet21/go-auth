package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idHasher implements the core.PasswordHasher interface.
type Argon2idHasher struct {
	time    uint32 // Iterations
	memory  uint32 // Memory usage in KiB
	threads uint8  // Degree of parallelism
	keyLen  uint32 // Length of the generated hash
	saltLen uint32 // Length of the random salt
}

// NewArgon2idHasher creates a hasher with your specified parameters.
func NewArgon2idHasher(time, memory uint32, threads uint8, keyLen, saltLen uint32) *Argon2idHasher {
	return &Argon2idHasher{
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
		saltLen: saltLen,
	}
}

// Hash generates a random salt, computes the Argon2id hash, and returns a PHC formatted string.
func (h *Argon2idHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, h.time, h.memory, h.threads, h.keyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, b64Salt, b64Hash)

	return encoded, nil
}

// Compare extracts the parameters and salt from the PHC string, re-hashes the input, and compares them securely.
func (h *Argon2idHasher) Compare(hashedPassword, plainPassword string) error {
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("invalid hash format")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return errors.New("incompatible argon2 version")
	}

	var memory, time uint32
	var threads uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return errors.New("invalid hash parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("failed to decode salt")
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errors.New("failed to decode hash")
	}

	comparisonHash := argon2.IDKey([]byte(plainPassword), salt, time, memory, threads, uint32(len(decodedHash)))

	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return nil
	}

	return errors.New("invalid password")
}
