package store

import (
	"sync"
	"time"
)

// userStoreImpl - это реализация UserStore, работающая в памяти.
type userStoreImpl struct {
	users map[string]*User // Храним пользователей по username
	mu    sync.RWMutex     // Для защиты доступа к мапе
}

// NewInMemoryUserStore создает новый экземпляр заглушки UserStore.
func NewInMemoryUserStore() UserStore {
	// несколько тестовых пользователей
	users := map[string]*User{
		"testuser": {
			ID:        "user-1",
			Username:  "testuser",
			Password:  "hashed_password_for_testuser", // Это будет хэш, но пока просто строка
			Email:     "testuser@example.com",
			CreatedAt: time.Now().Add(-24 * time.Hour),
			UpdatedAt: time.Now().Add(-12 * time.Hour),
		},
		"admin": {
			ID:        "user-2",
			Username:  "admin",
			Password:  "hashed_password_for_admin",
			Email:     "admin@example.com",
			CreatedAt: time.Now().Add(-48 * time.Hour),
			UpdatedAt: time.Now().Add(-24 * time.Hour),
		},
	}
	return &userStoreImpl{
		users: users,
	}
}

// Get реализует получение пользователя из хранилища (в памяти).
func (s *userStoreImpl) Get(username string) (*User, error) {
	s.mu.RLock()         // Блокируем для чтения
	defer s.mu.RUnlock() // Разблокируем при выходе из функции

	user, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound // Если пользователя нет, возвращаем ошибку
	}

	return user, nil
}
