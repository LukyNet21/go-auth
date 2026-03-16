# Gin adapter

Mounts auth routes onto any existing `*gin.RouterGroup` and provides `AuthMiddleware` for protecting your own routes.

## Routes

| Method | Path | Auth required |
|--------|------|---------------|
| `POST` | `/register` | - |
| `POST` | `/login` | - |
| `POST` | `/logout` | - |
| `POST` | `/refresh` | Refresh token cookie |
| `GET`  | `/me` | Bearer token |
| `POST` | `/change-password` | Bearer token |
| `POST` | `/logout-all` | Bearer token |

**Refresh token handling** - the refresh token is never exposed in the response body. On login it is written as an HTTP-only, `Secure`, `SameSite=Strict` cookie named `refresh_token`. `/refresh` reads from that cookie and returns a new access token. `/logout` clears the cookie and revokes the token server-side.

## Quick start

```go
import (
    "time"

    goauth "github.com/LukyNet21/go-auth"
    ginauth "github.com/LukyNet21/go-auth/adapters/gin"
    "github.com/LukyNet21/go-auth/providers/token"
    gormstore "github.com/LukyNet21/go-auth/store/gorm"
    "github.com/gin-gonic/gin"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

func main() {
    db, _ := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})

    store := gormstore.NewGormStore(db)
    store.Migrate() // optional: auto-create tables

    auth, _ := goauth.NewAuth(
        store,
        goauth.WithTokenProvider(
            token.NewHMACTokenProvider([]byte("your-secret"), 15*time.Minute),
        ),
    )

    r := gin.Default()
    ginauth.New(auth.Service).RegisterRoutes(r.Group("/auth"))
    r.Run(":8080")
}
```

## Mounting onto an existing router

```go
// All auth routes live under /api/v1/auth
v1 := r.Group("/api/v1")
ginauth.New(auth.Service).RegisterRoutes(v1.Group("/auth"))
```

## Using `AuthMiddleware` on your own routes

```go
handler := ginauth.New(auth.Service)
handler.RegisterRoutes(r.Group("/auth"))

// Protect any group with the same middleware
api := r.Group("/api", handler.AuthMiddleware())
api.GET("/dashboard", func(c *gin.Context) {
    claims, _ := ginauth.GetClaims(c)
    c.JSON(200, gin.H{"user_id": claims.UserID, "email": claims.Email})
})
```

`GetClaims` returns `(*models.Claims, bool)` - `false` if the middleware hasn't run or the token was invalid.
