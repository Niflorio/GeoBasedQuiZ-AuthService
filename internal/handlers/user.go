package handlers

import (
	"AuthService/internal/repository"
	"database/sql"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
	"time"
)

type UserHandler struct {
	userRepo *repository.UserRepository
}

func NewUserHandler(userRepo *repository.UserRepository) *UserHandler {
	return &UserHandler{userRepo: userRepo}
}

func (h *UserHandler) AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("userID") // Из JWT (добавлено ранее)
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		roles, err := h.userRepo.GetUserRoles(uuid.MustParse(userID))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles"})
			c.Abort()
			return
		}

		isAdmin := false
		for _, role := range roles {
			if role == "admin" {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (h *UserHandler) GetUsers(c *gin.Context) {
	query := `SELECT id, username, email, avatar_base64, status, is_verified, created_at, updated_at, deleted_at FROM user_profiles WHERE deleted_at IS NULL`
	rows, err := h.userRepo.Db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}
	defer rows.Close()

	var users []struct {
		ID           uuid.UUID  `json:"id"`
		Username     string     `json:"username"`
		Email        string     `json:"email"`
		AvatarBase64 *string    `json:"avatar_base64"`
		Status       string     `json:"status"`
		IsVerified   bool       `json:"is_verified"`
		CreatedAt    time.Time  `json:"created_at"`
		UpdatedAt    *time.Time `json:"updated_at"`
		DeletedAt    *time.Time `json:"deleted_at"`
	}

	for rows.Next() {
		var u struct {
			ID           uuid.UUID      `json:"id"`
			Username     string         `json:"username"`
			Email        string         `json:"email"`
			AvatarBase64 sql.NullString `json:"avatar_base64"`
			Status       string         `json:"status"`
			IsVerified   bool           `json:"is_verified"`
			CreatedAt    time.Time      `json:"created_at"`
			UpdatedAt    *time.Time     `json:"updated_at"`
			DeletedAt    *time.Time     `json:"deleted_at"`
		}
		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.AvatarBase64, &u.Status, &u.IsVerified, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan user"})
			return
		}
		var avatarStr *string
		if u.AvatarBase64.Valid {
			temp := u.AvatarBase64.String
			avatarStr = &temp
		} else {
			avatarStr = nil
		}

		users = append(users, struct {
			ID           uuid.UUID  `json:"id"`
			Username     string     `json:"username"`
			Email        string     `json:"email"`
			AvatarBase64 *string    `json:"avatar_base64"`
			Status       string     `json:"status"`
			IsVerified   bool       `json:"is_verified"`
			CreatedAt    time.Time  `json:"created_at"`
			UpdatedAt    *time.Time `json:"updated_at"`
			DeletedAt    *time.Time `json:"deleted_at"`
		}{
			ID:           u.ID,
			Username:     u.Username,
			Email:        u.Email,
			AvatarBase64: avatarStr,
			Status:       u.Status,
			IsVerified:   u.IsVerified,
			CreatedAt:    u.CreatedAt,
			UpdatedAt:    u.UpdatedAt,
			DeletedAt:    u.DeletedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (h *UserHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")
	u, err := h.userRepo.GetUserByID(uuid.MustParse(userID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": u})
}

func (h *UserHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	var req struct {
		AvatarBase64 *string `json:"avatar_base64"`
		Status       *string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `UPDATE user_profiles SET avatar_base64 = COALESCE($1, avatar_base64), status = COALESCE($2, status), updated_at = NOW() WHERE id = $3 AND deleted_at IS NULL`
	_, err := h.userRepo.Db.Exec(query, req.AvatarBase64, req.Status, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user updated"})
}

func (h *UserHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	query := `UPDATE user_profiles SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL`
	result, err := h.userRepo.Db.Exec(query, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}

func (h *UserHandler) AddUserRole(c *gin.Context) {
	userID := c.Param("id")
	var req struct {
		Role string `json:"role" binding:"required,oneof=user content-moderator admin"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `INSERT INTO user_roles (user_id, role, granted_at, granted_by) VALUES ($1, $2, NOW(), $3) ON CONFLICT (user_id, role) DO NOTHING`
	_, err := h.userRepo.Db.Exec(query, userID, req.Role, c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add role"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "role added"})
}

func (h *UserHandler) RemoveUserRole(c *gin.Context) {
	userID := c.Param("id")
	role := c.Param("role")
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role = $2`
	result, err := h.userRepo.Db.Exec(query, userID, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove role"})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "role removed"})
}
