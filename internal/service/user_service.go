package service

type UserService interface {
	//  ValidateCredentials проверяет соответств. имя и пароль от уч. записи
	ValidateCredentials(username, password string) (bool, error)

	// создает новый JWT токен для указанного имени пользователя
	GenerateToken(username string) (string, error)

	// обновляет токен если он еще не истек
	RefreshToken(refreshToken string) (string, error)
}
