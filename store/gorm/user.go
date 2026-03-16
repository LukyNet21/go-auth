package gorm_store

import (
	"context"
	"errors"

	"github.com/LukyNet21/go-auth/models"
	"gorm.io/gorm"
)

func (s *GormStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	user, err := gorm.G[userRow](s.db).Where("id = ?", id).First(ctx)
	if err != nil {
		return nil, err
	}

	return user.toDomain(), nil
}

func (s *GormStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := gorm.G[userRow](s.db).Where("email = ?", email).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return user.toDomain(), nil
}
