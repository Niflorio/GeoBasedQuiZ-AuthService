package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"AuthService/internal/models"
	"AuthService/internal/repository"
	"AuthService/internal/utils"
)

type AuthHandler struct {
	userRepo *repository.UserRepository
}

func NewAuthHandler(userRepo *repository.UserRepository) *AuthHandler {
	return &AuthHandler{userRepo: userRepo}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверяем уникальность username
	existingUser, _, err := h.userRepo.GetUserByUsername(req.Username)
	if err == nil && existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		return
	}

	// Проверяем уникальность email
	query := `SELECT id FROM user_profiles WHERE email = $1 AND deleted_at IS NULL`
	var userID uuid.UUID
	err = h.userRepo.Db.QueryRow(query, req.Email).Scan(&userID)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
		return
	}
	if err != sql.ErrNoRows {
		log.Printf("Failed to check email existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Создаем нового пользователя
	user := &models.User{
		Username: req.Username,
		Email:    req.Email,
	}

	err = h.userRepo.CreateUser(user, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	token, err := h.userRepo.CreateVerificationToken(user.ID)
	if err != nil {
		log.Printf("Failed to create verification token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create verification token"})
		return
	}

	// Отправляем письмо асинхронно
	go func() {
		if err := utils.SendVerificationEmail(user.Email, user.Username, token); err != nil {
			log.Printf("Failed to send verification email: %v", err)
		}
	}()

	c.JSON(http.StatusCreated, gin.H{
		"message": "user created successfully",
		"user_id": user.ID,
	})

}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	userID, err := h.userRepo.VerifyUserByToken(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "email verified successfully",
		"user_id": userID,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Login attempt: username=%s", req.Username)

	// Получаем пользователя из базы данных
	user, authData, err := h.userRepo.GetUserByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !user.IsVerified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "email not verified"})
		return
	}
	// Проверяем, заблокирован ли аккаунт
	if authData.IsLocked {
		if authData.LockedUntil != nil && authData.LockedUntil.After(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("account is locked until %s", authData.LockedUntil.Format(time.RFC3339))})
			return
		}
		// Если блокировка истекла, разблокируем
		if authData.LockedUntil != nil && authData.LockedUntil.Before(time.Now()) {
			authData.IsLocked = false
			authData.FailedAttempts = 0
			authData.LockedUntil = nil
			query := `UPDATE  	auth_data SET is_locked = false, failed_attempts = 0, locked_until = NULL WHERE user_id = $1`
			if _, err := h.userRepo.Db.Exec(query, user.ID); err != nil {
				log.Printf("Failed to unlock account: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				return
			}
		}
	}

	log.Printf("User found: %s, checking password...", user.Username)

	// Проверяем пароль
	if !utils.CheckPassword(req.Password, authData.PasswordHash) {
		// Увеличиваем счетчик неудачных попыток
		log.Printf("Password mismatch for user: %s", user.Username)
		if err := h.userRepo.IncrementFailedAttempts(user.ID); err != nil {
			log.Printf("Failed to increment failed attempts: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	query := `UPDATE auth_data SET failed_attempts = 0, is_locked = false, locked_until = NULL WHERE user_id = $1`
	if _, err := h.userRepo.Db.Exec(query, user.ID); err != nil {
		log.Printf("Failed to reset failed attempts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Обновляем время последнего входа
	err = h.userRepo.UpdateLastLogin(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Генерируем JWT токен
	accessToken, expiresAt, err := utils.GenerateJWT(user.ID, user.Username, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	// Генерируем refresh токен
	refreshToken := utils.GenerateRefreshToken()

	deviceInfoBytes, err := json.Marshal(map[string]string{"user_agent": c.Request.UserAgent()})
	if err != nil {
		log.Printf("Failed to marshal device info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Создаем сессию
	session := &models.Session{
		SessionID:    uuid.New(),
		UserID:       user.ID,
		DeviceInfo:   string(deviceInfoBytes),
		IPAddress:    c.ClientIP(),
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour), // 7 дней
		IsRevoked:    false,
		RefreshToken: refreshToken,
	}

	err = h.userRepo.CreateSession(session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	go func() {
		device := c.Request.UserAgent()
		if err := utils.SendLoginNotification(user.Email, user.Username, c.ClientIP(), device); err != nil {
			log.Printf("Failed to send login notification to %s: %v", user.Email, err)
		}
	}()

	// Получаем роли пользователя
	roles, err := h.userRepo.GetUserRoles(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user roles"})
		return
	}

	response := models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		User:         *user,
		Roles:        roles,
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   response,
		"status": "success",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Валидируем refresh-токен
	session, err := h.userRepo.GetSessionByRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or revoked refresh token"})
		return
	}

	// Проверяем, не истек ли срок действия сессии
	if session.ExpiresAt.Before(time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	// Получаем информацию о пользователе
	user, err := h.userRepo.GetUserByID(session.UserID)
	if err != nil {
		log.Printf("Failed to get user by ID %s: %v", session.UserID, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	// Генерируем новый access-токен
	accessToken, expiresAt, err := utils.GenerateJWT(user.ID, user.Username, user.Email)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	// Генерируем новый refresh-токен (ротация)
	newRefreshToken := utils.GenerateRefreshToken()

	// Обновляем сессию
	session.RefreshToken = newRefreshToken
	session.IssuedAt = time.Now()
	session.ExpiresAt = time.Now().Add(7 * 24 * time.Hour) // 7 дней
	session.IsRevoked = false

	if err := h.userRepo.UpdateSession(session); err != nil {
		log.Printf("Failed to update session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session"})
		return
	}

	// Получаем роли пользователя
	roles, err := h.userRepo.GetUserRoles(user.ID)
	if err != nil {
		log.Printf("Failed to get user roles: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user roles"})
		return
	}

	response := models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
		User:         *user,
		Roles:        roles,
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   response,
		"status": "success",
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req models.RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Отзываем сессию
	if err := h.userRepo.RevokeSession(req.RefreshToken); err != nil {
		log.Printf("Failed to revoke session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "successfully logged out",
		"status":  "success",
	})
}

// ValidateToken - endpoint для проверки токена другими сервисами
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	expectedToken := os.Getenv("SERVICE_SECRET_TOKEN")
	serviceToken := c.GetHeader("X-Service-Token")

	if serviceToken != expectedToken {
		c.JSON(http.StatusForbidden, gin.H{
			"valid": false,
			"error": "invalid service token",
		})
		return
	}
	if authHeader == "" {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": "authorization header is required",
		})
		return
	}

	// Извлекаем токен из заголовка
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": "invalid authorization format",
		})
		return
	}

	tokenString := tokenParts[1]

	// Валидация JWT токена
	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": "invalid token: " + err.Error(),
		})
		return
	}

	// Получаем информацию о пользователе
	user, err := h.userRepo.GetUserByID(claims.UserID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": "user not found",
		})
		return
	}

	// Проверяем, не удален ли пользователь
	if user.DeletedAt != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": "user account deleted",
		})
		return
	}

	/*
		if !user.IsVerified {
			c.JSON(http.StatusOK, gin.H{
				"valid": false,
				"error": "email not verified",
			})
			return
		}
	*/

	// Получаем роли пользователя
	roles, err := h.userRepo.GetUserRoles(claims.UserID)
	if err != nil {
		roles = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user": gin.H{
			"id":         user.ID.String(),
			"username":   user.Username,
			"email":      user.Email,
			"deleted_at": user.DeletedAt,
			"roles":      roles,
		},
	})
}
func AuthMiddleware(userRepo *repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
			c.Abort()
			return
		}

		// Извлекаем токен из заголовка
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			c.Abort()
			return
		}

		tokenString := tokenParts[1]

		// Валидируем токен
		claims, err := utils.ValidateJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Добавляем информацию о пользователе в контекст
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)

		c.Next()
	}
}
