package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/LukyNet21/go-auth/models"
	"github.com/google/uuid"
)

type AuthService struct {
	store         Store
	hasher        PasswordHasher
	tokenProvider TokenProvider
}

func NewAuthService(s Store, h PasswordHasher, t TokenProvider) *AuthService {
	return &AuthService{
		store:         s,
		hasher:        h,
		tokenProvider: t,
	}
}

// RegisterWithPassword registers new user using email and password.
func (s *AuthService) RegisterWithPassword(ctx context.Context, email, password string) (*models.User, error) {
	if email == "" || password == "" {
		return nil, models.ErrInvalidCredentials
	}

	_, err := s.store.GetUserByEmail(ctx, email)
	if err == nil {
		return nil, models.ErrEmailAlreadyInUse
	}
	if !errors.Is(err, models.ErrUserNotFound) {
		return nil, err
	}

	passwordHash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	userID := uuid.NewString()
	identityID := uuid.NewString()

	u := models.User{
		ID:        userID,
		Email:     email,
		CreatedAt: now,
		UpdatedAt: now,
	}

	i := models.Identity{
		ID:             identityID,
		UserID:         userID,
		Provider:       models.ProviderLocal,
		ProviderUserID: email,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	p := models.ProviderPassword{
		IdentityID:   identityID,
		PasswordHash: passwordHash,
		UpdatedAt:    now,
	}

	if err := s.store.CreateUserWithLocalIdentity(ctx, &u, &i, &p); err != nil {
		return nil, err
	}

	return &u, nil
}

// LoginWithPassword authenticates a user by email and password, then issues
// an access token and a refresh token.
func (s *AuthService) LoginWithPassword(ctx context.Context, email, password, userAgent, ipAddress string) (*models.AuthResult, error) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, models.ErrInvalidCredentials
	}

	identity, err := s.store.GetLocalIdentityByUserID(ctx, user.ID)
	if err != nil {
		return nil, models.ErrInvalidCredentials
	}

	passwordHash, err := s.store.GetPasswordHash(ctx, identity.ID)
	if err != nil {
		return nil, models.ErrInvalidCredentials
	}

	if err := s.hasher.Compare(passwordHash, password); err != nil {
		return nil, models.ErrInvalidCredentials
	}

	accessToken, err := s.tokenProvider.GenerateAccessToken(user)
	if err != nil {
		return nil, err
	}

	rawRefresh, err := s.tokenProvider.GenerateSecureString(32)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256([]byte(rawRefresh))
	rt := &models.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: hex.EncodeToString(sum[:]),
		UserAgent: userAgent,
		IPAddress: ipAddress,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateRefreshToken(ctx, rt); err != nil {
		return nil, err
	}

	return &models.AuthResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
	}, nil
}

func (s *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	sum := sha256.Sum256([]byte(refreshToken))
	rt, err := s.store.GetRefreshTokenByHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return "", err
	}

	user, err := s.store.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return "", err
	}

	accessToken, err := s.tokenProvider.GenerateAccessToken(user)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	sum := sha256.Sum256([]byte(refreshToken))
	rt, err := s.store.GetRefreshTokenByHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}

	if s.store.RevokeRefreshToken(ctx, rt.ID) != nil {
		return models.ErrFailedToRevokeToken
	}

	return nil
}

func (s *AuthService) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	identity, err := s.store.GetLocalIdentityByUserID(ctx, userID)
	if err != nil {
		return models.ErrInvalidCredentials
	}

	passwordHash, err := s.store.GetPasswordHash(ctx, identity.ID)
	if err != nil {
		return models.ErrInvalidCredentials
	}

	if err := s.hasher.Compare(passwordHash, oldPassword); err != nil {
		return models.ErrInvalidCredentials
	}

	newPasswordHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	if err := s.store.UpdatePasswordHash(ctx, identity.ID, newPasswordHash); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	if err := s.store.RevokeAllRefreshTokensByUserID(ctx, userID); err != nil {
		return models.ErrFailedToRevokeToken
	}
	return nil
}
