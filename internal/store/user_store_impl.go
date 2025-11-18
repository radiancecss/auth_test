package store

import "fmt"

// Реализация хранилища пользователей в памяти
type InMemoryUserStore struct {
	users map[string]User
}

// Создаем новое хранилище пользователей
func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users: make(map[string]User),
	}
}

// Добавить пользователя в хранилище
func (s *InMemoryUserStore) AddUser(username string, hashedPassword []byte) error {
	if _, exists := s.users[username]; exists {
		return fmt.Errorf("user already exists")
	}
	s.users[username] = User{
		Username:       username,
		HashedPassword: hashedPassword,
	}
	return nil
}

// Получить пользователя из хранилища
func (s *InMemoryUserStore) Get(username string) (User, error) {
	user, exists := s.users[username]
	if !exists {
		return User{}, fmt.Errorf("user not found")
	}
	return user, nil
}
