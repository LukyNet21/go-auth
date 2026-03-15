package goauth

import (
	"errors"

	"github.com/LukyNet21/go-auth/core"
	"github.com/LukyNet21/go-auth/providers/password"
)

type Auth struct {
	store         core.Store
	hasher        core.PasswordHasher
	tokenProvider core.TokenProvider
	mailer        core.Mailer

	Service *core.AuthService
}

type Option func(*Auth)

func NewAuth(store core.Store, opts ...Option) (*Auth, error) {
	a := &Auth{
		store: store,
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.hasher == nil {
		a.hasher = password.NewArgon2idHasher(4, 64*1024, 4, 32, 16)
	}

	if a.tokenProvider == nil {
		return nil, errors.New("a TokenProvider is required: use WithTokenProvider()")
	}

	a.Service = core.NewAuthService(a.store, a.hasher, a.tokenProvider)

	return a, nil
}

func WithPasswordAuth(hasher core.PasswordHasher) Option {
	return func(a *Auth) {
		a.hasher = hasher
	}
}

func WithTokenProvider(tp core.TokenProvider) Option {
	return func(a *Auth) {
		a.tokenProvider = tp
	}
}
