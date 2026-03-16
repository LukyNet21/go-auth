package ginauth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware validates the Bearer JWT in the Authorization header and
// stores the claims in the context. Aborts with 401 on missing or invalid tokens.
func (h *GinHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, errResp("authorization header required"))
			return
		}

		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, errResp("authorization header must be: Bearer <token>"))
			return
		}

		claims, err := h.tokenProvider.ValidateAccessToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, errResp("invalid or expired token"))
			return
		}

		SetClaims(c, claims)
		c.Next()
	}
}
