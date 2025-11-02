package utils

import (
	"fmt"
	"html"
	"net/smtp"
	"os"
	"time"
)

func SendVerificationEmail(email, username, token string) error {
	safeUsername := html.EscapeString(username)
	safeToken := html.EscapeString(token)

	// Настройки Gmail SMTP
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	from := os.Getenv("GMAIL_EMAIL")            // ваш@gmail.com
	password := os.Getenv("GMAIL_APP_PASSWORD") // пароль приложения

	// Текст письма
	subject := "Subject: Подтверждение регистрации в GeoBaseQuiz\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := fmt.Sprintf(`<h1>Привет, %s!</h1><p>Подтверди свой email, нажав на ссылку:</p><p><a href="http://localhost:8080/auth/verify?token=%s">Подтвердить</a></p><p>Ссылка действительна 24 часа.</p>`, safeUsername, safeToken)

	msg := []byte(subject + mime + body)

	// Аутентификация и отправка
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, msg)
	return err
}

func SendLoginNotification(email, username, ip, device string) error {
	// Аналогичная реализация для уведомлений о входе
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	from := os.Getenv("GMAIL_EMAIL")
	password := os.Getenv("GMAIL_APP_PASSWORD")

	subject := "Subject: Новый вход в аккаунт\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := fmt.Sprintf(`<h1>Привет, %s!</h1><p>Вы вошли в систему %s с IP: %s (устройство: %s).</p><p>Если это не вы, немедленно свяжитесь с поддержкой.</p>`, username, time.Now().Format("2006-01-02 15:04"), ip, device)

	msg := []byte(subject + mime + body)

	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, msg)
	return err
}
