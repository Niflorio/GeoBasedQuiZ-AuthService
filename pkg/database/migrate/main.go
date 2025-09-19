package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
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
		log.Fatal("Usage: migrate [up|down|force|version]")
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
	default:
		log.Fatal("Unknown command:", cmd)
	}
}
