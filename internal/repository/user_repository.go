package repository

import (
	"database/sql"
	"errors"
	"time"

	"AuthService/internal/models"
	"AuthService/internal/utils"

	"github.com/google/uuid"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(user *models.User, password string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Создаем пользователя
	user.ID = uuid.New()
	user.CreatedAt = time.Now()

	query := `INSERT INTO user_profiles (id, username, email, avatar_base64, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err = tx.Exec(query, user.ID, user.Username, user.Email, user.AvatarBase64, user.CreatedAt)
	if err != nil {
		return err
	}

	// Хешируем пароль
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return err
	}

	// Создаем запись аутентификации
	authQuery := `INSERT INTO auth_data (user_id, password_hash, created_at) VALUES ($1, $2, $3)`
	_, err = tx.Exec(authQuery, user.ID, hashedPassword, time.Now())
	if err != nil {
		return err
	}

	// Назначаем роль по умолчанию
	roleQuery := `INSERT INTO user_roles (user_id, role, granted_at) VALUES ($1, $2, $3)`
	_, err = tx.Exec(roleQuery, user.ID, "user", time.Now())
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (r *UserRepository) GetUserByUsername(username string) (*models.User, *models.AuthData, error) {
	query := `
        SELECT u.id, u.username, u.email, u.avatar_base64, u.status, u.created_at, u.updated_at, u.deleted_at,
               a.password_hash, a.oauth_provider, a.oauth_id, a.last_login, a.failed_attempts, a.is_locked, a.created_at
        FROM user_profiles u
        JOIN auth_data a ON u.id = a.user_id
        WHERE u.username = $1 AND u.deleted_at IS NULL
    `

	var user models.User
	var authData models.AuthData

	// Добавляем временную переменную для сканирования avatar_base64
	var avatar sql.NullString

	err := r.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &avatar, &user.Status, // ← Изменили здесь
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&authData.PasswordHash, &authData.OAuthProvider, &authData.OAuthID,
		&authData.LastLogin, &authData.FailedAttempts, &authData.IsLocked, &authData.CreatedAt,
	)

	// После сканирования преобразуем sql.NullString в *string
	if avatar.Valid {
		user.AvatarBase64 = &avatar.String
	} else {
		user.AvatarBase64 = nil
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, errors.New("user not found")
		}
		return nil, nil, err
	}

	return &user, &authData, nil
}

func (r *UserRepository) CreateSession(session *models.Session) error {
	query := `
        INSERT INTO sessions (session_id, user_id, device_info, ip_address, issued_at, expires_at, is_revoked, refresh_token)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `

	_, err := r.db.Exec(
		query,
		session.SessionID,
		session.UserID,
		session.DeviceInfo,
		session.IPAddress,
		session.IssuedAt,
		session.ExpiresAt,
		session.IsRevoked,
		session.RefreshToken,
	)

	return err
}

func (r *UserRepository) GetUserRoles(userID uuid.UUID) ([]string, error) {
	query := `SELECT role FROM user_roles WHERE user_id = $1`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (r *UserRepository) UpdateLastLogin(userID uuid.UUID) error {
	query := `UPDATE auth_data SET last_login = $1 WHERE user_id = $2`
	_, err := r.db.Exec(query, time.Now(), userID)
	return err
}
