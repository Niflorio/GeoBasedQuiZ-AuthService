# GeoBasedQuiZ Auth Service

Центральный сервис аутентификации и управления пользователями платформы GeoBasedQuiZ. Отвечает за регистрацию, подтверждение электронной почты, вход, управление сессиями, роли и проверку JWT-токенов для остальных микросервисов.

## Возможности

- регистрация пользователей с проверкой уникальности логина и email;
- хеширование паролей с помощью bcrypt;
- подтверждение электронной почты;
- выдача access- и refresh-токенов;
- обновление и отзыв пользовательских сессий;
- получение профиля и ролей текущего пользователя;
- административное управление пользователями и ролями;
- ограничение частоты запросов для чувствительных endpoints;
- отправка транзакционных писем через SMTP;
- централизованная валидация токенов для других сервисов.

## API

### Публичные endpoints

| Метод | Endpoint | Назначение |
|---|---|---|
| POST | `/auth/register` | Регистрация пользователя |
| POST | `/auth/login` | Вход и получение пары токенов |
| POST | `/auth/refresh` | Обновление access- и refresh-токенов |
| POST | `/auth/logout` | Отзыв пользовательской сессии |
| GET | `/auth/verify` | Подтверждение электронной почты |
| GET | `/health` | Проверка работоспособности сервиса |

### Защищённые endpoints

| Метод | Endpoint | Назначение |
|---|---|---|
| GET | `/api/profile` | Получение идентификатора текущего пользователя |
| GET | `/api/my-roles` | Получение ролей текущего пользователя |

### Административные endpoints

| Метод | Endpoint | Назначение |
|---|---|---|
| GET | `/admin/users` | Получение списка пользователей |
| GET | `/admin/users/:id` | Получение пользователя |
| PUT | `/admin/users/:id` | Изменение данных пользователя |
| DELETE | `/admin/users/:id` | Мягкое удаление пользователя |
| POST | `/admin/users/:id/roles` | Добавление роли |
| DELETE | `/admin/users/:id/roles/:role` | Удаление роли |

## Структура

```text
cmd/server/              точка входа
internal/handlers/       HTTP-обработчики
internal/middleware/     аутентификация и проверка доступа
internal/models/         модели запросов, ответов и данных
internal/repository/     работа с PostgreSQL
internal/utils/          JWT, пароли и отправка email
migrations/              миграции схемы базы данных
```

## Конфигурация

Создайте `.env` на основе `.env.example`.

```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=change_me
DB_NAME=geobasedquiz_auth

JWT_SECRET=change_me
JWT_REFRESH_SECRET=change_me

GMAIL_EMAIL=example@gmail.com
GMAIL_APP_PASSWORD=change_me

SERVER_PORT=8080
```

Не добавляйте `.env`, реальные пароли, JWT-секреты и пароли приложений в Git.

## Локальный запуск

```bash
go mod download
go run ./cmd/server
```

Перед запуском примените SQL-миграции из каталога `migrations/` с помощью утилиты миграций, включённой в репозиторий.

## Безопасность

Сервис использует хеширование паролей, access/refresh JWT-токены, отзыв сессий, проверку ролей, валидацию входных данных и rate limiting. Секреты должны передаваться только через переменные окружения.

## Связанные репозитории

- [GeoBasedQuiZ — обзор проекта](https://github.com/Niflorio/GeoBasedQuiZ)
- [GeoData Service](https://github.com/Niflorio/GeoBasedQuiZ-GeoDataService)
- [Achievements Service](https://github.com/Niflorio/GeoBasedQuiZ-AchievementsService)
- [Feedback Service](https://github.com/Niflorio/GeoBasedQuiZ-FeedbackService)
