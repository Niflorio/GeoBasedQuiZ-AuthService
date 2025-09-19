package handlers

import (
	"fmt"
	"log"
	"net/http"
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

	// Проверяем, существует ли пользователь
	existingUser, _, err := h.userRepo.GetUserByUsername(req.Username)
	if err == nil && existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
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

	c.JSON(http.StatusCreated, gin.H{
		"message": "user created successfully",
		"user_id": user.ID,
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

	// Проверяем, заблокирован ли аккаунт
	if authData.IsLocked {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account is locked"})
		return
	}

	log.Printf("User found: %s, checking password...", user.Username)

	// Проверяем пароль
	if !utils.CheckPassword(req.Password, authData.PasswordHash) {
		// Увеличиваем счетчик неудачных попыток
		log.Printf("Password mismatch for user: %s", user.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
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

	deviceInfo := fmt.Sprintf(`{"user_agent": "%s"}`, c.Request.UserAgent())

	// Создаем сессию
	session := &models.Session{
		SessionID:    uuid.New(),
		UserID:       user.ID,
		DeviceInfo:   deviceInfo,
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
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   response,
		"roles":  roles,
		"status": "success",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Реализация обновления токена
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// Реализация выхода из системы
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
