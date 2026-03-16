package ginauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/LukyNet21/go-auth/models"
	"github.com/gin-gonic/gin"
)

const refreshTokenCookie = "refresh_token"

// setRefreshCookie writes the refresh token as an HTTP-only, Secure, SameSite=Strict cookie.
func setRefreshCookie(c *gin.Context, token string, ttl time.Duration) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(
		refreshTokenCookie,
		token,
		int(ttl.Seconds()),
		"/",
		"",
		true, // Secure
		true, // HttpOnly
	)
}

// clearRefreshCookie removes the refresh token cookie.
func clearRefreshCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(refreshTokenCookie, "", -1, "/", "", true, true)
}

func (h *GinHandler) register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	user, err := h.service.RegisterWithPassword(c.Request.Context(), req.Email, req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrEmailAlreadyInUse):
			c.JSON(http.StatusConflict, errResp("email already in use"))
		default:
			c.JSON(http.StatusInternalServerError, errResp("registration failed"))
		}
		return
	}

	c.JSON(http.StatusCreated, meResponse{
		ID:       user.ID,
		Email:    user.Email,
		Username: user.Username,
	})
}

func (h *GinHandler) login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	result, err := h.service.LoginWithPassword(
		c.Request.Context(),
		req.Email,
		req.Password,
		c.GetHeader("User-Agent"),
		c.ClientIP(),
	)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, errResp("invalid credentials"))
		default:
			c.JSON(http.StatusInternalServerError, errResp("login failed"))
		}
		return
	}

	setRefreshCookie(c, result.RefreshToken, 30*24*time.Hour)
	c.JSON(http.StatusOK, loginResponse{AccessToken: result.AccessToken})
}

func (h *GinHandler) refresh(c *gin.Context) {
	raw, err := c.Cookie(refreshTokenCookie)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("refresh token cookie missing"))
		return
	}

	accessToken, err := h.service.RefreshAccessToken(c.Request.Context(), raw)
	if err != nil {
		clearRefreshCookie(c)
		c.JSON(http.StatusUnauthorized, errResp("invalid or expired refresh token"))
		return
	}

	c.JSON(http.StatusOK, loginResponse{AccessToken: accessToken})
}

func (h *GinHandler) logout(c *gin.Context) {
	raw, err := c.Cookie(refreshTokenCookie)
	if err != nil {
		c.Status(http.StatusNoContent)
		return
	}

	clearRefreshCookie(c)

	if err := h.service.Logout(c.Request.Context(), raw); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("logout failed"))
		return
	}

	c.Status(http.StatusNoContent)
}
