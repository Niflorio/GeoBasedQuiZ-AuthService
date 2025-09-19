package models

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	Username     string     `json:"username" db:"username"`
	Email        string     `json:"email" db:"email"`
	AvatarBase64 string     `json:"avatar_base64,omitempty" db:"avatar_base64"`
	Status       string     `json:"status,omitempty" db:"status"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty" db:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

type UserRole struct {
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	Role      string     `json:"role" db:"role"`
	GrantedAt time.Time  `json:"granted_at" db:"granted_at"`
	GrantedBy *uuid.UUID `json:"granted_by,omitempty" db:"granted_by"`
	Scope     string     `json:"scope,omitempty" db:"scope"`
}
