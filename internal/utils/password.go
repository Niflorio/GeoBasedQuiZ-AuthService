package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword создает bcrypt хеш от пароля
func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// CheckPassword проверяет, соответствует ли пароль хешу
func CheckPassword(password string, hash []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	return err == nil
}
