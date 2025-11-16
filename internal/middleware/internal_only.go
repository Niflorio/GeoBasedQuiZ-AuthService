// internal/middleware/internal.go
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// InternalOnlyMiddleware разрешает доступ только с доверенных IP
func InternalOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := getClientIP(c.Request)

		// Разрешаем только localhost и внутренние IP
		allowed := false
		if clientIP == "127.0.0.1" || clientIP == "::1" {
			allowed = true
		}
		// Для Docker сетей
		if strings.HasPrefix(clientIP, "172.") || strings.HasPrefix(clientIP, "10.") || strings.HasPrefix(clientIP, "192.168.") {
			allowed = true
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "access denied",
				"code":  "INTERNAL_ACCESS_ONLY",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func getClientIP(r *http.Request) string {
	// Проверяем заголовки прокси
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
