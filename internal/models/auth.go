package models

import (
	"github.com/google/uuid"
	"time"
)

type AuthData struct {
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	PasswordHash   []byte     `json:"-" db:"password_hash"`
	OAuthProvider  *string    `json:"oauth_provider,omitempty" db:"oauth_provider"`
	OAuthID        *string    `json:"oauth_id,omitempty" db:"oauth_id"`
	LastLogin      *time.Time `json:"last_login,omitempty" db:"last_login"`
	FailedAttempts int        `json:"failed_attempts" db:"failed_attempts"`
	IsLocked       bool       `json:"is_locked" db:"is_locked"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
}

type Session struct {
	SessionID    uuid.UUID `json:"session_id" db:"session_id"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	DeviceInfo   string    `json:"device_info" db:"device_info"`
	IPAddress    string    `json:"ip_address" db:"ip_address"`
	IssuedAt     time.Time `json:"issued_at" db:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	IsRevoked    bool      `json:"is_revoked" db:"is_revoked"`
	RefreshToken string    `json:"refresh_token" db:"refresh_token"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type AuthResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         User      `json:"user"`
}
