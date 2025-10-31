package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Загружаем переменные окружения
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Подключаемся к базе данных
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Создаем экземпляр драйвера для миграций
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatal("Failed to create migrations driver:", err)
	}

	// Создаем экземпляр миграции
	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		log.Fatal("Failed to create migrations instance:", err)
	}

	// Выполняем команду в зависимости от аргументов
	if len(os.Args) < 2 {
		log.Fatal("Usage: migrate [up|down|force|version|create-admin]")
	}

	cmd := os.Args[1]
	switch cmd {
	case "up":
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Fatal("Failed to apply migrations:", err)
		}
		log.Println("Migrations applied successfully")
	case "down":
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatal("Failed to revert migrations:", err)
		}
		log.Println("Migrations reverted successfully")
	case "force":
		if len(os.Args) < 3 {
			log.Fatal("Force requires a version argument")
		}
		versionStr := os.Args[2]
		version, err := strconv.Atoi(versionStr) //
		if err != nil {
			log.Fatal("Invalid version number:", versionStr)
		}
		if err := m.Force(version); err != nil {
			log.Fatal("Failed to force migrations version:", err)
		}
		log.Println("Migration version forced successfully")
	case "version":
		version, dirty, err := m.Version()
		if err != nil {
			log.Fatal("Failed to get migrations version:", err)
		}
		log.Printf("Current version: %d, dirty: %t", version, dirty)
	case "create-admin":
		if err := createAdmin(db); err != nil {
			log.Fatal("Failed to create admin:", err)
		}
		log.Println("Admin creation completed")
	default:
		log.Fatal("Unknown command:", cmd)
	}
}

// createAdmin создаёт админа в БД, используя данные из .env
func createAdmin(db *sql.DB) error {
	username := os.Getenv("ADMIN_USERNAME")
	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")
	if username == "" || email == "" || password == "" {
		return fmt.Errorf("missing ADMIN_USERNAME, ADMIN_EMAIL, or ADMIN_PASSWORD in .env")
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Проверяем, есть ли админ
	var adminExists bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM user_roles WHERE role = 'admin')").Scan(&adminExists)
	if err != nil {
		return fmt.Errorf("failed to check admin existence: %w", err)
	}
	if adminExists {
		log.Println("Admin already exists, skipping creation")
		return nil
	}

	// Создаём админа в транзакции
	userID := uuid.New()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	// Вставка в user_profiles
	_, err = tx.Exec(`
		INSERT INTO user_profiles (id, username, email, avatar_base64, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (email) DO NOTHING`,
		userID, username, email, nil, time.Now())
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to insert user profile: %w", err)
	}

	// Вставка в auth_data
	_, err = tx.Exec(`
		INSERT INTO auth_data (user_id, password_hash, created_at)
		VALUES ($1, $2, $3)`,
		userID, string(hashedPassword), time.Now())
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to insert auth data: %w", err)
	}

	// Вставка в user_roles
	_, err = tx.Exec(`
		INSERT INTO user_roles (user_id, role, granted_at)
		VALUES ($1, $2, $3)`,
		userID, "admin", time.Now())
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to insert user role: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Admin created successfully: %s (%s)", username, email)
	return nil
}
