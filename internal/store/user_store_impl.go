package store

import (
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ErrUserNotFound - ошибка, когда пользователь не найден.
var ErrUserNotFound = errors.New("user not found")

// User представляет пользователя.
type User struct {
	ID             string
	Username       string
	HashedPassword []byte // Храним хеш пароля как []byte
	Email          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UserStore определяет методы для работы с пользователями.
type UserStore interface {
	Get(username string) (*User, error)
}

// userStoreImpl - это реализация UserStore, работающая в памяти.
type userStoreImpl struct {
	users map[string]*User // Храним пользователей по username
	mu    sync.RWMutex     // Для защиты доступа к мапе
}

// NewInMemoryUserStore создает новый экземпляр UserStore в памяти.
func NewInMemoryUserStore() UserStore {
	// Пароль для тестового пользователя
	testUserPassword := "password123"
	hashedPasswordForTestuser, err := bcrypt.GenerateFromPassword([]byte(testUserPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("FATAL: Failed to hash password for testuser: %v", err)
	}

	// Пароль для админа
	adminPassword := "adminpass" // Замени на хеш, если есть возможность
	hashedPasswordForAdmin, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("FATAL: Failed to hash password for admin: %v", err)
	}

	users := map[string]*User{
		"testuser": {
			ID:             "user-1",
			Username:       "testuser",
			HashedPassword: hashedPasswordForTestuser, // Сохраняем хеш
			Email:          "testuser@example.com",
			CreatedAt:      time.Now().Add(-24 * time.Hour),
			UpdatedAt:      time.Now().Add(-12 * time.Hour),
		},
		"admin": {
			ID:             "user-2",
			Username:       "admin",
			HashedPassword: hashedPasswordForAdmin, // Сохраняем хеш
			Email:          "admin@example.com",
			CreatedAt:      time.Now().Add(-48 * time.Hour),
			UpdatedAt:      time.Now().Add(-24 * time.Hour),
		},
	}

	return &userStoreImpl{
		users: users,
	}
}

// Get реализует получение пользователя из хранилища.
func (s *userStoreImpl) Get(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	return user, nil
}
