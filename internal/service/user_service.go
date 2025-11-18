package service

// Интерфейс для сервиса пользователей
type UserService interface {
	// Проверка правильности логина и пароля
	ValidateCredentials(username, password string) (bool, error)

	// Генерация токена
	GenerateToken(username string) (string, error)

	// Обновление токена
	RefreshToken(refreshToken string) (string, error)

	// Проверка валидности токена
	ValidateToken(tokenString string) (string, error)

	// Добавление нового пользователя
	AddUser(username, password string) error
}
