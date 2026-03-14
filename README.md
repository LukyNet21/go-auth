# go-auth

> **Work in progress**: not ready for any use.

A Go authentication library providing a pluggable auth service with support for local (email/password) authentication, JWT access tokens, and refresh token sessions.

## Features

- Email/password registration and login
- Password hashing via Argon2id (default) or bcrypt
- JWT acc   ess token generation
- Refresh token management
- Extensible via interfaces (`Store`, `TokenProvider`, `Mailer`)

## Requirements

- Go 1.25+
