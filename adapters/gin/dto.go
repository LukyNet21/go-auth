package ginauth

import "time"

// registerRequest is the body for POST /auth/register.
type registerRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

// loginRequest is the body for POST /auth/login.
type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// loginResponse is returned after a successful login or token refresh.
type loginResponse struct {
	AccessToken string `json:"access_token"`
}

// meResponse is the public representation of the authenticated user.
type meResponse struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Username        string     `json:"username"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
}

// changePasswordRequest is the body for POST /auth/change-password.
type changePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// errorResponse is the standard error envelope.
type errorResponse struct {
	Error string `json:"error"`
}

func errResp(msg string) errorResponse {
	return errorResponse{Error: msg}
}
