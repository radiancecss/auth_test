package store

import "errors"

// Ошибка, когда пользователь не найден
var ErrUserNotFound = errors.New("user not found")

// Структура пользователя
type User struct {
	Username       string
	HashedPassword []byte
}

// Интерфейс для работы с хранилищем пользователей
type UserStore interface {
	AddUser(username string, hashedPassword []byte) error
	Get(username string) (User, error)
}
