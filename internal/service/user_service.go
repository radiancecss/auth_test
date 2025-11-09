package service

import (
	"errors"
)

// UserService определяет операции, которые могут быть выполнены с пользователями.
type UserService interface {
	// ValidateCredentials проверяет соответств. имя и пароль от уч. записи
	ValidateCredentials(username, password string) (bool, error)

	// создает новый JWT токен для указанного имени пользователя
	GenerateToken(username string) (string, error)

	// обновляет токен если он еще не истек
	RefreshToken(refreshToken string) (string, error)

	// ValidateToken проверяет JWT-токен и возвращает имя пользователя, если он валиден.
	ValidateToken(token string) (string, error)
}

// Ошибки, которые могут возвращаться методами сервиса
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token is expired")
)
