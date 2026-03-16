package main

import (
	"log"
	"net/http"
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
	db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	store := gormstore.NewGormStore(db)

	if err := store.Migrate(); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	tp := token.NewHMACTokenProvider(
		[]byte("replace-with-a-secure-random-secret"),
		15*time.Minute,
	)

	auth, err := goauth.NewAuth(
		store,
		goauth.WithTokenProvider(tp),
	)
	if err != nil {
		log.Fatalf("init auth: %v", err)
	}

	r := gin.Default()

	// Mount auth routes at /auth.
	// Protected routes (GET /auth/me, POST /auth/change-password,
	// POST /auth/logout-all) require a valid Bearer token.
	handler := ginauth.New(auth.Service)
	handler.RegisterRoutes(r.Group("/auth"))

	// Example of re-using AuthMiddleware on your own routes:
	api := r.Group("/api", handler.AuthMiddleware())
	api.GET("/profile", func(c *gin.Context) {
		claims, _ := ginauth.GetClaims(c)
		c.JSON(http.StatusOK, gin.H{"user_id": claims.UserID})
	})

	log.Println("listening on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("server: %v", err)
	}
}
