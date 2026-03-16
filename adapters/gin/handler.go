package ginauth

import (
	"github.com/LukyNet21/go-auth/core"
	"github.com/gin-gonic/gin"
)

// GinHandler wires the auth service to a Gin router.
type GinHandler struct {
	service       *core.AuthService
	tokenProvider core.TokenProvider
}

// New creates a GinHandler. The TokenProvider must be the same instance used
// by the AuthService so that tokens issued and validated use the same key.
func New(service *core.AuthService) *GinHandler {
	return &GinHandler{
		service:       service,
		tokenProvider: service.TokenProvider(),
	}
}

// RegisterRoutes mounts all auth routes onto rg.
//
//	POST /register
//	POST /login
//	POST /logout
//	POST /refresh
//	GET  /me               (uses AuthMiddleware)
//	POST /change-password  (uses AuthMiddleware)
//	POST /logout-all       (uses AuthMiddleware)
func (h *GinHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/register", h.register)
	rg.POST("/login", h.login)
	rg.POST("/logout", h.logout)
	rg.POST("/refresh", h.refresh)

	authenticated := rg.Group("", h.AuthMiddleware())
	authenticated.GET("/me", h.me)
	authenticated.POST("/change-password", h.changePassword)
	authenticated.POST("/logout-all", h.logoutAll)
}
