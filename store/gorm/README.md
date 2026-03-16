# GORM store

Implements the `core.Store` interface using GORM. Supports any database GORM supports - SQLite, PostgreSQL, MySQL, and others.

## Usage

```go
import gormstore "github.com/LukyNet21/go-auth/store/gorm"

store := gormstore.NewGormStore(db)
```

Pass the store to `goauth.NewAuth` via the first argument.

## Schema management

```go
// Let the library create and migrate its own tables.
if err := store.Migrate(); err != nil {
    log.Fatal(err)
}
```

`Migrate()` calls GORM's `AutoMigrate` on the four auth tables:

| Table | Description |
|-------|-------------|
| `users` | Core user records |
| `identities` | Auth provider links per user |
| `provider_passwords` | Hashed passwords for local auth |
| `refresh_tokens` | Active refresh token sessions |

If you manage migrations yourself (golang-migrate, Goose, etc.) skip `Migrate()` and create the tables from your own migration files instead.
