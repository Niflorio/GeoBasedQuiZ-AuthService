package utils

import (
	"fmt"
	"html"
	"os"
	"time"

	"github.com/resend/resend-go/v2"
)

func SendLoginNotification(email, username, ip, device string) error {
	client := resend.NewClient(os.Getenv("EMAIL_API_KEY"))
	params := &resend.SendEmailRequest{
		From:    os.Getenv("EMAIL_FROM"),
		To:      []string{email},
		Subject: "New Login Notification",
		Html:    fmt.Sprintf(`<h1>Привет, %s!</h1><p>Вы вошли в систему %s с IP: %s (устройство: %s).</p><p>Если это не вы, <a href="your-reset-link">сбросьте пароль</a>.</p>`, username, time.Now().Format("2006-01-02 15:04"), ip, device),
	}
	_, err := client.Emails.Send(params)
	return err
}

func SendVerificationEmail(email, username, token string) error {
	client := resend.NewClient(os.Getenv("EMAIL_API_KEY"))
	safeUsername := html.EscapeString(username)
	safeToken := html.EscapeString(token)

	params := &resend.SendEmailRequest{
		From:    os.Getenv("EMAIL_FROM"),
		To:      []string{email},
		Subject: "Подтверждение регистрации",
		Html:    fmt.Sprintf(`<h1>Привет, %s!</h1><p>Подтверди свой email, нажав на ссылку:</p><p><a href="http://localhost:8080/auth/verify?token=%s">Подтвердить</a></p><p>Ссылка действительна 24 часа.</p>`, safeUsername, safeToken),
	}
	_, err := client.Emails.Send(params)
	return err
}
