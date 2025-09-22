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
	Db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{Db: db}
}

func (r *UserRepository) CreateUser(user *models.User, password string) error {
	tx, err := r.Db.Begin()
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
        SELECT u.id,
               u.username,
               u.email,
               u.avatar_base64,
               u.status,
               u.created_at,
               u.updated_at,
               u.deleted_at,
               a.password_hash,
               a.oauth_provider,
               a.oauth_id,
               a.last_login,
               a.failed_attempts,
               a.is_locked,
               a.created_at,
               a.locked_until
        FROM user_profiles u
        JOIN auth_data a ON u.id = a.user_id
        WHERE u.username = $1 AND u.deleted_at IS NULL
    `

	var user models.User
	var authData models.AuthData
	var lockedUntil sql.NullTime

	// Добавляем временную переменную для сканирования avatar_base64
	var avatar sql.NullString

	err := r.Db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &avatar, &user.Status,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&authData.PasswordHash, &authData.OAuthProvider, &authData.OAuthID,
		&authData.LastLogin, &authData.FailedAttempts, &authData.IsLocked, &authData.CreatedAt, &lockedUntil,
	)

	// После сканирования преобразуем sql.NullString в *string
	if avatar.Valid {
		user.AvatarBase64 = &avatar.String
	} else {
		user.AvatarBase64 = nil
	}

	if lockedUntil.Valid {
		authData.LockedUntil = &lockedUntil.Time
	} else {
		authData.LockedUntil = nil
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

	_, err := r.Db.Exec(
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

func (r *UserRepository) GetSessionByRefreshToken(refreshToken string) (*models.Session, error) {
	query := `
        SELECT session_id, user_id, device_info, ip_address, issued_at, expires_at, is_revoked, refresh_token
        FROM sessions
        WHERE refresh_token = $1 AND is_revoked = false
    `

	var session models.Session
	err := r.Db.QueryRow(query, refreshToken).Scan(
		&session.SessionID,
		&session.UserID,
		&session.DeviceInfo,
		&session.IPAddress,
		&session.IssuedAt,
		&session.ExpiresAt,
		&session.IsRevoked,
		&session.RefreshToken,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid or revoked refresh token")
		}
		return nil, err
	}

	return &session, nil
}

func (r *UserRepository) UpdateSession(session *models.Session) error {
	query := `
        UPDATE sessions
        SET refresh_token = $1, issued_at = $2, expires_at = $3, is_revoked = $4
        WHERE session_id = $5
    `

	_, err := r.Db.Exec(
		query,
		session.RefreshToken,
		session.IssuedAt,
		session.ExpiresAt,
		session.IsRevoked,
		session.SessionID,
	)

	return err
}

func (r *UserRepository) RevokeSession(refreshToken string) error {
	query := `UPDATE sessions SET is_revoked = true WHERE refresh_token = $1`
	_, err := r.Db.Exec(query, refreshToken)
	return err
}

func (r *UserRepository) GetUserByID(userID uuid.UUID) (*models.User, error) {
	query := `
        SELECT id, username, email, avatar_base64, status, created_at, updated_at, deleted_at
        FROM user_profiles
        WHERE id = $1 AND deleted_at IS NULL
    `

	var user models.User
	var avatar sql.NullString

	err := r.Db.QueryRow(query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &avatar, &user.Status,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if avatar.Valid {
		user.AvatarBase64 = &avatar.String
	} else {
		user.AvatarBase64 = nil
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetUserRoles(userID uuid.UUID) ([]string, error) {
	query := `SELECT role FROM user_roles WHERE user_id = $1`

	rows, err := r.Db.Query(query, userID)
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
	_, err := r.Db.Exec(query, time.Now(), userID)
	return err
}

func (r *UserRepository) IncrementFailedAttempts(userID uuid.UUID) error {
	const maxAttempts = 5
	const lockDuration = 30 * time.Minute

	query := `
        UPDATE auth_data 
        SET failed_attempts = failed_attempts + 1,
            is_locked = CASE WHEN failed_attempts + 1 >= $1 THEN true ELSE is_locked END,
            locked_until = CASE WHEN failed_attempts + 1 >= $1 THEN $2 ELSE locked_until END
        WHERE user_id = $3
    `

	_, err := r.Db.Exec(query, maxAttempts, time.Now().Add(lockDuration), userID)
	return err
}
