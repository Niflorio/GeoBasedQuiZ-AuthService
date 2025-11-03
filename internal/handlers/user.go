package handlers

import (
	"AuthService/internal/repository"
	"database/sql"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"log"
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
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		// Преобразуем в uuid.UUID
		uid, ok := userID.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
			c.Abort()
			return
		}

		roles, err := h.userRepo.GetUserRoles(uid)
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
	result, err := h.userRepo.Db.Exec(query, req.AvatarBase64, req.Status, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
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

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}

func (h *UserHandler) AddUserRole(c *gin.Context) {
	userIDParam := c.Param("id")

	// Преобразуем строковый ID в uuid.UUID
	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID format"})
		return
	}

	var req struct {
		Role string `json:"role" binding:"required,oneof=user content-moderator admin"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Преобразуем currentUserID в uuid.UUID
	grantedBy, ok := currentUserID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type"})
		return
	}

	// Проверяем, существует ли пользователь
	_, err = h.userRepo.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	query := `INSERT INTO user_roles (user_id, role, granted_at, granted_by) VALUES ($1, $2, NOW(), $3) ON CONFLICT (user_id, role) DO NOTHING`
	result, err := h.userRepo.Db.Exec(query, userID, req.Role, grantedBy)
	if err != nil {
		log.Printf("Failed to add role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add role", "details": err.Error()}) // Добавим детали ошибки для отладки
		return
	}

	// Проверяем, была ли добавлена роль
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "role already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role added"})
}

func (h *UserHandler) RemoveUserRole(c *gin.Context) {
	userIDParam := c.Param("id")

	// Преобразуем строковый ID в uuid.UUID
	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID format"})
		return
	}

	role := c.Param("role")
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role = $2`
	result, err := h.userRepo.Db.Exec(query, userID, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove role", "details": err.Error()}) // Добавим детали ошибки
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role removed"})
}
