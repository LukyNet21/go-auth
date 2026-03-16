# go-auth

> **Work in progress**: not ready for production use.

A pluggable Go authentication library with email/password auth, JWT access tokens, and refresh token sessions. Built around clean interfaces so you can swap the database, password hasher, or token provider without touching the core logic.

## Features

- Email/password registration and login
- Password hashing via Argon2id (default) or bcrypt
- JWT access tokens - HMAC (HS256) or ECDSA (ES256)
- Refresh tokens stored server-side, delivered as HTTP-only cookies
- Refresh token rotation
- Gin adapter with ready-made routes and `AuthMiddleware`
- GORM store (SQLite, PostgreSQL, MySQL)
- Extensible via `Store`, `TokenProvider`, `PasswordHasher`, and `Mailer` interfaces

## Requirements

Go 1.25+

## Token providers

```go
// HMAC - shared secret, simpler setup
token.NewHMACTokenProvider([]byte("secret"), 15*time.Minute)

// ECDSA - asymmetric, useful when multiple services need to verify tokens
token.NewECDSATokenProvider(privateKey, 15*time.Minute)
```

## Password hashers

```go
// Argon2id (default - no explicit option needed)
password.NewArgon2idHasher(time, memory, threads, keyLen, saltLen)

// bcrypt
password.NewBcryptHasher(cost)
```

## Web adapters

- [Gin](adapters/gin/) - ready-made routes, `AuthMiddleware`, HTTP-only cookie refresh tokens

## Stores

- [GORM](store/gorm/) - SQLite, PostgreSQL, MySQL. Optional `Migrate()` for auto-managed schema.

## Examples

- [GORM + Gin + SQLite](examples/gorm-gin-sqlite/)
