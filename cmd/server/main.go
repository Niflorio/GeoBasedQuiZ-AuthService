package main

import (
	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"AuthService/internal/handlers"
	"AuthService/internal/repository"
	_ "AuthService/internal/utils"
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
	userHandler := handlers.NewUserHandler(userRepo)

	// Настраиваем роутер
	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	loginLimit, _ := strconv.ParseFloat(os.Getenv("RATE_LIMIT_LOGIN"), 64)
	if loginLimit == 0 {
		loginLimit = 5 // 5 запросов в минуту
	}
	registerLimit, _ := strconv.ParseFloat(os.Getenv("RATE_LIMIT_REGISTER"), 64)
	if registerLimit == 0 {
		registerLimit = 3 // 3 запроса в 5 минут
	}
	refreshLimit, _ := strconv.ParseFloat(os.Getenv("RATE_LIMIT_REFRESH"), 64)
	if refreshLimit == 0 {
		refreshLimit = 10 // 10 запросов в минуту
	}
	verifyLimit, _ := strconv.ParseFloat(os.Getenv("RATE_LIMIT_VERIFY"), 64)
	if verifyLimit == 0 {
		verifyLimit = 5 // 5 запросов в час
	}
	validateLimit, _ := strconv.ParseFloat(os.Getenv("RATE_LIMIT_VALIDATE"), 64)
	if validateLimit == 0 {
		validateLimit = 100 // 100 запросов в минуту на сервис
	}

	// Маршруты аутентификации
	authRoutes := router.Group("/auth")
	{
		authRoutes.POST("/register", RateLimitMiddleware(registerLimit, 5*time.Minute), authHandler.Register)
		authRoutes.POST("/login", RateLimitMiddleware(loginLimit, time.Minute), authHandler.Login)
		authRoutes.POST("/refresh", RateLimitMiddleware(refreshLimit, time.Minute), authHandler.RefreshToken)
		authRoutes.POST("/logout", RateLimitMiddleware(refreshLimit, time.Minute), authHandler.Logout)
		authRoutes.GET("/verify", RateLimitMiddleware(verifyLimit, time.Hour), authHandler.VerifyEmail)

		authRoutes.GET("/validate-token",
			RateLimitMiddleware(validateLimit, time.Minute),
			//middleware.InternalOnlyMiddleware(),
			authHandler.ValidateToken)
	}

	adminGroup := router.Group("/admin", handlers.AuthMiddleware(userRepo), userHandler.AdminOnly())
	{
		adminGroup.GET("/users", userHandler.GetUsers)
		adminGroup.GET("/users/:id", userHandler.GetUser)
		adminGroup.PUT("/users/:id", userHandler.UpdateUser)
		adminGroup.DELETE("/users/:id", userHandler.DeleteUser)
		adminGroup.POST("/users/:id/roles", userHandler.AddUserRole)
		adminGroup.DELETE("/users/:id/roles/:role", userHandler.RemoveUserRole)
	}

	// Защищенные маршруты (пример)
	protected := router.Group("/api")
	protected.Use(handlers.AuthMiddleware(userRepo))
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID, exists := c.Get("userID")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			// Безопасное преобразование типа - используем type assertion
			uid, ok := userID.(uuid.UUID)
			if !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user_id": uid})
		})

		protected.GET("/my-roles", func(c *gin.Context) {
			userID, exists := c.Get("userID")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			uid, ok := userID.(uuid.UUID)
			if !ok {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID type"})
				return
			}

			roles, err := userRepo.GetUserRoles(uid)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"user_id":  uid,
				"roles":    roles,
				"is_admin": isAdmin(roles),
			})
		})
	}

	routes := router.Routes()
	log.Println("Registered routes:")
	for _, route := range routes {
		log.Printf("%s %s", route.Method, route.Path)
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

// Функция для создания rate limiter middleware
func RateLimitMiddleware(maxRequests float64, ttl time.Duration) gin.HandlerFunc {
	lmt := tollbooth.NewLimiter(maxRequests, &limiter.ExpirableOptions{DefaultExpirationTTL: ttl})
	lmt.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"}) // Для прокси
	lmt.SetMessage("You have reached the maximum number of requests. Please try again later.")
	lmt.SetMessageContentType("application/json")
	lmt.SetStatusCode(http.StatusTooManyRequests)

	return func(c *gin.Context) {
		httpError := tollbooth.LimitByRequest(lmt, c.Writer, c.Request)
		if httpError != nil {
			c.JSON(httpError.StatusCode, gin.H{"error": httpError.Message})
			c.Abort()
			return
		}
		c.Next()
	}
}

func isAdmin(roles []string) bool {
	for _, role := range roles {
		if role == "admin" {
			return true
		}
	}
	return false
}
