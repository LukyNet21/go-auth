package gorm_store

import (
	"context"

	"github.com/LukyNet21/go-auth/models"
	"gorm.io/gorm"
)

func (s *GormStore) GetLocalIdentityByUserID(ctx context.Context, userID string) (*models.Identity, error) {
	identity, err := gorm.G[identityRow](s.db).Where("user_id = ? AND provider = ?", userID, models.ProviderLocal).First(ctx)
	if err != nil {
		return nil, err
	}

	return identity.toDomain(), nil
}

func (s *GormStore) GetPasswordHash(ctx context.Context, identityID string) (string, error) {
	password, err := gorm.G[providerPasswordRow](s.db).Where("identity_id = ?", identityID).First(ctx)
	if err != nil {
		return "", err
	}

	return password.PasswordHash, nil
}

func (s *GormStore) CreateUserWithLocalIdentity(ctx context.Context, user *models.User, identity *models.Identity, password *models.ProviderPassword) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := gorm.G[userRow](tx).Create(ctx, userRowFromDomain(user)); err != nil {
			return err
		}
		if err := gorm.G[identityRow](tx).Create(ctx, identityRowFromDomain(identity)); err != nil {
			return err
		}
		if err := gorm.G[providerPasswordRow](tx).Create(ctx, providerPasswordRowFromDomain(password)); err != nil {
			return err
		}
		return nil
	})
}

func (s *GormStore) UpdatePasswordHash(ctx context.Context, identityID, newHash string) error {
	_, err := gorm.G[providerPasswordRow](s.db).Where("identity_id = ?", identityID).Update(ctx, "password_hash", newHash)
	return err
}
