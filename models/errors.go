package models

import "errors"

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrIdentityNotFound    = errors.New("identity not found")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrTokenExpired        = errors.New("token expired or revoked")
	ErrEmailAlreadyInUse   = errors.New("email is already in use")
	ErrOTPInvalid          = errors.New("invalid or expired OTP code")
	ErrOTPMayBeBruteForced = errors.New("too many failed OTP attempts")
	ErrCouldNotCreateUser  = errors.New("could not create user")
	ErrFailedToRevokeToken = errors.New("failed to refresh token")
)
