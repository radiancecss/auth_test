package store

import (
	"errors"
	"time"
)

// ErrUserNotFound - ошибка, когда пользователь не найден в хранилище.
var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // Пароль не должен передаваться в JSON
	Email    string `json:"email"`
	// Другие поля, если нужны
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserStore interface {
	Get(username string) (*User, error)
}
