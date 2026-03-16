package gorm_store

import "gorm.io/gorm"

type GormStore struct {
	db *gorm.DB
}

func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db}
}

// Migrate runs GORM AutoMigrate for all auth tables. Call this once at
// startup when you want the library to manage its own schema.
func (s *GormStore) Migrate() error {
	return s.db.AutoMigrate(
		&userRow{},
		&identityRow{},
		&providerPasswordRow{},
		&refreshTokenRow{},
	)
}
