package ginauth

import (
	"errors"
	"net/http"

	"github.com/LukyNet21/go-auth/models"
	"github.com/gin-gonic/gin"
)

func (h *GinHandler) changePassword(c *gin.Context) {
	claims, ok := GetClaims(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, errResp("unauthorized"))
		return
	}

	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	if err := h.service.ChangePassword(c.Request.Context(), claims.UserID, req.OldPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, errResp("current password is incorrect"))
		default:
			c.JSON(http.StatusInternalServerError, errResp("password change failed"))
		}
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *GinHandler) me(c *gin.Context) {
	claims, ok := GetClaims(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, errResp("unauthorized"))
		return
	}

	user, err := h.service.GetUser(c.Request.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, errResp("user not found"))
			return
		}
		c.JSON(http.StatusInternalServerError, errResp("failed to fetch user"))
		return
	}

	c.JSON(http.StatusOK, meResponse{
		ID:              user.ID,
		Email:           user.Email,
		Username:        user.Username,
		EmailVerifiedAt: user.EmailVerifiedAt,
	})
}

func (h *GinHandler) logoutAll(c *gin.Context) {
	claims, ok := GetClaims(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, errResp("unauthorized"))
		return
	}

	if err := h.service.LogoutAll(c.Request.Context(), claims.UserID); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("failed to revoke sessions"))
		return
	}

	c.Status(http.StatusNoContent)
}
