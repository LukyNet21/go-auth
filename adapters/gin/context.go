package ginauth

import (
	"github.com/LukyNet21/go-auth/models"
	"github.com/gin-gonic/gin"
)

const claimsKey = "auth_claims"

// SetClaims stores validated JWT claims in the gin context.
func SetClaims(c *gin.Context, claims *models.Claims) {
	c.Set(claimsKey, claims)
}

// GetClaims retrieves the JWT claims set by AuthMiddleware.
// Returns (nil, false) if the middleware has not run or authentication failed.
func GetClaims(c *gin.Context) (*models.Claims, bool) {
	v, ok := c.Get(claimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*models.Claims)
	return claims, ok
}
