package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"

	"AuthService/internal/models"
	"AuthService/internal/repository"
	"AuthService/internal/utils"
)

// Глобальные переменные для тестов
var (
	db       *sql.DB
	mock     sqlmock.Sqlmock
	userRepo *repository.UserRepository
	handler  *AuthHandler
	router   *gin.Engine
)

// TestMain настраивает окружение и моки перед запуском тестов
func TestMain(m *testing.M) {
	// Получаем текущую рабочую директорию для отладки
	wd, err := os.Getwd()
	if err != nil {
		panic("Failed to get working directory: " + err.Error())
	}
	fmt.Printf("Current working directory: %s\n", wd)

	// Явно указываем путь к .env в корне проекта
	envPath := filepath.Join(wd, "../..", ".env")
	fmt.Printf("Attempting to load .env from: %s\n", envPath)
	if err := godotenv.Load(envPath); err != nil {
		panic(fmt.Sprintf("Failed to load .env file from %s: %v", envPath, err))
	}

	// Проверяем, что JWT_SECRET загружен
	if os.Getenv("JWT_SECRET") == "" {
		panic("JWT_SECRET is not set in .env")
	}

	// Инициализируем мок БД
	db, mock, err = sqlmock.New()
	if err != nil {
		panic("Failed to create sqlmock: " + err.Error())
	}
	defer db.Close()

	// Настраиваем зависимости
	userRepo = repository.NewUserRepository(db)
	handler = NewAuthHandler(userRepo)
	router = setupAuthTestRouter(handler)

	// Запускаем тесты
	os.Exit(m.Run())
}

// setupAuthTestRouter настраивает роутер для тестов
func setupAuthTestRouter(handler *AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	authRoutes := r.Group("/auth")
	{
		authRoutes.POST("/register", handler.Register)
	}
	return r
}

// createJSONRequest создаёт HTTP-запрос с JSON-телом
func createJSONRequest(method, url string, body interface{}) (*http.Request, *httptest.ResponseRecorder) {
	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	return req, w
}

func TestAuthHandler_Register(t *testing.T) {
	// Очищаем ожидания перед каждым тестом
	defer mock.ExpectationsWereMet()

	t.Run("Successful Registration", func(t *testing.T) {
		// Описание: Успешная регистрация нового пользователя
		// Ожидание: HTTP 201, пользователь создан, токен верификации сгенерирован
		reqBody := models.RegisterRequest{
			Username: "newuser",
			Email:    "new@example.com",
			Password: "StrongPass1!",
		}

		// Мокаем запросы к БД
		// 1. Проверка username (не существует)
		mock.ExpectQuery(`SELECT id, username, email, avatar_base64, status, is_verified, created_at, updated_at, deleted_at, password_hash, oauth_provider, oauth_id, last_login, failed_attempts, is_locked, created_at, locked_until FROM user_profiles u JOIN auth_data a ON u.id = a.user_id WHERE u.username = \$1 AND u.deleted_at IS NULL`).
			WithArgs(reqBody.Username).
			WillReturnError(sql.ErrNoRows)
		// 2. Проверка email (не существует)
		mock.ExpectQuery(`SELECT id FROM user_profiles WHERE email = \$1 AND deleted_at IS NULL`).
			WithArgs(reqBody.Email).
			WillReturnError(sql.ErrNoRows)
		// 3. Создание пользователя (транзакция)
		mock.ExpectBegin()
		userID := uuid.New()
		mock.ExpectExec(`INSERT INTO user_profiles \(id, username, email, avatar_base64, created_at, is_verified\) VALUES \(\$1, \$2, \$3, \$4, \$5, \$6\)`).
			WithArgs(userID, reqBody.Username, reqBody.Email, nil, sqlmock.AnyArg(), false).
			WillReturnResult(sqlmock.NewResult(1, 1))
		hashedPass, _ := utils.HashPassword(reqBody.Password)
		mock.ExpectExec(`INSERT INTO auth_data \(user_id, password_hash, created_at\) VALUES \(\$1, \$2, \$3\)`).
			WithArgs(userID, hashedPass, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`INSERT INTO user_roles \(user_id, role, granted_at\) VALUES \(\$1, \$2, \$3\)`).
			WithArgs(userID, "user", sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		// 4. Создание verification token
		mock.ExpectExec(`INSERT INTO verification_tokens \(token, user_id, expires_at, created_at\) VALUES \(\$1, \$2, \$3, \$4\)`).
			WithArgs(sqlmock.AnyArg(), userID, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		req, w := createJSONRequest("POST", "/auth/register", reqBody)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "user created successfully", resp["message"])
		assert.NotEmpty(t, resp["user_id"])
	})

	t.Run("Duplicate Username", func(t *testing.T) {
		// Описание: Регистрация с существующим username
		// Ожидание: HTTP 409 Conflict, ошибка "username already exists"
		reqBody := models.RegisterRequest{
			Username: "existinguser",
			Email:    "new@example.com",
			Password: "StrongPass1!",
		}

		// Мокаем: username существует
		userID := uuid.New()
		rows := sqlmock.NewRows([]string{
			"id", "username", "email", "avatar_base64", "status", "is_verified", "created_at", "updated_at", "deleted_at",
			"password_hash", "oauth_provider", "oauth_id", "last_login", "failed_attempts", "is_locked", "created_at", "locked_until",
		}).AddRow(userID, reqBody.Username, "existing@example.com", nil, "", true, time.Now(), nil, nil, []byte("hash"), nil, nil, nil, 0, false, time.Now(), nil)
		mock.ExpectQuery(`SELECT id, username, email, avatar_base64, status, is_verified, created_at, updated_at, deleted_at, password_hash, oauth_provider, oauth_id, last_login, failed_attempts, is_locked, created_at, locked_until FROM user_profiles u JOIN auth_data a ON u.id = a.user_id WHERE u.username = \$1 AND u.deleted_at IS NULL`).
			WithArgs(reqBody.Username).
			WillReturnRows(rows)

		req, w := createJSONRequest("POST", "/auth/register", reqBody)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "username already exists", resp["error"])
	})

	t.Run("Duplicate Email", func(t *testing.T) {
		// Описание: Регистрация с существующим email
		// Ожидание: HTTP 409 Conflict, ошибка "email already exists"
		reqBody := models.RegisterRequest{
			Username: "newuser",
			Email:    "existing@example.com",
			Password: "StrongPass1!",
		}

		// Мокаем: username не существует, email существует
		mock.ExpectQuery(`SELECT id, username, email, avatar_base64, status, is_verified, created_at, updated_at, deleted_at, password_hash, oauth_provider, oauth_id, last_login, failed_attempts, is_locked, created_at, locked_until FROM user_profiles u JOIN auth_data a ON u.id = a.user_id WHERE u.username = \$1 AND u.deleted_at IS NULL`).
			WithArgs(reqBody.Username).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery(`SELECT id FROM user_profiles WHERE email = \$1 AND deleted_at IS NULL`).
			WithArgs(reqBody.Email).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

		req, w := createJSONRequest("POST", "/auth/register", reqBody)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "email already exists", resp["error"])
	})

	t.Run("Invalid Password Length", func(t *testing.T) {
		// Описание: Регистрация с коротким паролем
		// Ожидание: HTTP 400 Bad Request
		reqBody := models.RegisterRequest{
			Username: "newuser",
			Email:    "new@example.com",
			Password: "short",
		}

		req, w := createJSONRequest("POST", "/auth/register", reqBody)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp["error"], "RegisterRequest.Password")
		assert.Contains(t, resp["error"], "min")
	})

	t.Run("Invalid Email Format", func(t *testing.T) {
		// Описание: Регистрация с некорректным email
		// Ожидание: HTTP 400 Bad Request
		reqBody := models.RegisterRequest{
			Username: "newuser",
			Email:    "invalid-email",
			Password: "StrongPass1!",
		}

		req, w := createJSONRequest("POST", "/auth/register", reqBody)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp["error"], "email")
	})

	t.Run("Database Error", func(t *testing.T) {
		// Описание: Ошибка при создании пользователя
		// Ожидание: HTTP 500 Internal Server Error
		reqBody := models.RegisterRequest{
			Username: "newuser",
			Email:    "new@example.com",
			Password: "StrongPass1!",
		}

		// Мокаем: username и email не существуют, но ошибка при вставке
		mock.ExpectQuery(`SELECT id, username, email, avatar_base64, status, is_verified, created_at, updated_at, deleted_at, password_hash, oauth_provider, oauth_id, last_login, failed_attempts, is_locked, created_at, locked_until FROM user_profiles u JOIN auth_data a ON u.id = a.user_id WHERE u.username = \$1 AND u.deleted_at IS NULL`).
			WithArgs(reqBody.Username).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery(`SELECT id FROM user_profiles WHERE email = \$1 AND deleted_at IS NULL`).
			WithArgs(reqBody.Email).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectBegin()
		mock.ExpectExec(`INSERT INTO user_profiles \(id, username, email, avatar_base64, created_at, is_verified\) VALUES \(\$1, \$2, \$3, \$4, \$5, \$6\)`).
			WillReturnError(sql.ErrConnDone)

		req, w := createJSONRequest("POST", "/auth/register", reqBody)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "internal server error", resp["error"])
	})
}
