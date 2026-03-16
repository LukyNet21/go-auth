package gorm_store

import (
	"context"

	"github.com/LukyNet21/go-auth/models"
	"gorm.io/gorm"
)

func (s *GormStore) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return gorm.G[refreshTokenRow](s.db).Create(ctx, refreshTokenRowFromDomain(token))
}

func (s *GormStore) GetRefreshToken(ctx context.Context, tokenID string) (*models.RefreshToken, error) {
	token, err := gorm.G[refreshTokenRow](s.db).Where("id = ?", tokenID).First(ctx)
	if err != nil {
		return nil, err
	}
	return token.toDomain(), nil
}

func (s *GormStore) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	token, err := gorm.G[refreshTokenRow](s.db).Where("token_hash = ?", tokenHash).First(ctx)
	if err != nil {
		return nil, err
	}
	return token.toDomain(), nil
}

func (s *GormStore) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	_, err := gorm.G[refreshTokenRow](s.db).Where("id = ?", tokenID).Update(ctx, "revoked", true)
	return err
}

func (s *GormStore) RevokeAllRefreshTokensByUserID(ctx context.Context, userID string) error {
	_, err := gorm.G[refreshTokenRow](s.db).Where("user_id = ?", userID).Update(ctx, "revoked", true)
	return err
}
