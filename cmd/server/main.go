package main

import (
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"AuthService/internal/handlers"
	"AuthService/internal/repository"
)

func main() {
	// Загружаем переменные окружения
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Инициализируем базу данных
	db, err := repository.InitDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Инициализируем репозиторий и обработчики
	userRepo := repository.NewUserRepository(db)
	authHandler := handlers.NewAuthHandler(userRepo)

	// Настраиваем роутер
	router := gin.Default()

	// Маршруты аутентификации
	authRoutes := router.Group("/auth")
	{
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/refresh", authHandler.RefreshToken)
		authRoutes.POST("/logout", handlers.AuthMiddleware(userRepo), authHandler.Logout)
	}

	// Защищенные маршруты (пример)
	protected := router.Group("/api")
	protected.Use(handlers.AuthMiddleware(userRepo))
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("userID").(uuid.UUID)
			c.JSON(http.StatusOK, gin.H{"user_id": userID})
		})
	}

	// Запускаем сервер
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
