package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"auth_test/internal/store"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// UserServiceImpl - конкретная реализация UserService.
type UserServiceImpl struct {
	UserStore     store.UserStore
	JWTSecret     string
	TokenLifetime time.Duration
}

func NewUserServiceImpl(userStore store.UserStore, jwtSecret string, tokenLifetimeMinutes int) UserService {
	log.Println("Initializing UserServiceImpl...")
	return &UserServiceImpl{
		UserStore:     userStore,
		JWTSecret:     jwtSecret,
		TokenLifetime: time.Duration(tokenLifetimeMinutes) * time.Minute,
	}
}

// ValidateCredentials проверка токена
func (s *UserServiceImpl) ValidateCredentials(username, password string) (bool, error) {
	log.Printf("Validating credentials for user: %s", username)

	// Получаем пользователя из хранилища
	user, err := s.UserStore.Get(username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			log.Println("User not found.")
			return false, ErrInvalidCredentials // Всегда возвращаем ErrInvalidCredentials, чтобы не раскрывать, существует ли пользователь
		}
		// Другие ошибки при доступе к хранилищу
		log.Printf("Error accessing user store: %v", err)
		return false, fmt.Errorf("failed to retrieve user: %w", err)
	}

	// Сравнивает введенный пароль с хэшем пароля пользователя
	// bcrypt.CompareHashAndPassword возвращает nil, если пароли совпадают
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		// Если ошибка, значит пароли не совпали (или другая ошибка bcrypt)
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Println("Password mismatch.")
			return false, ErrInvalidCredentials
		}
		// Другие ошибки bcrypt
		log.Printf("Error comparing password hash: %v", err)
		return false, fmt.Errorf("failed to compare password: %w", err)
	}

	// Если ошибок нет, значит пароли совпадают
	log.Printf("Credentials are valid for user: %s", username)
	return true, nil
}

// GenerateToken реализует создание нового JWT.
func (s *UserServiceImpl) GenerateToken(username string) (string, error) {
	log.Printf("Generating token for user: %s", username)

	// Определяет время истечения токена
	expirationTime := time.Now().Add(s.TokenLifetime)

	// Создает claims (заявления) для JWT
	claims := &jwt.RegisteredClaims{
		Subject:   username,                           // Идентификатор пользователя
		ExpiresAt: jwt.NewNumericDate(expirationTime), // Время истечения
		IssuedAt:  jwt.NewNumericDate(time.Now()),     // Время выдачи
	}

	// Создает новый токен с указанным алгоритмом подписи и claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписывает токен секретным ключом
	tokenString, err := token.SignedString([]byte(s.JWTSecret))
	if err != nil {
		log.Printf("Error signing token: %v", err)
		return "", errors.New("failed to generate token")
	}

	log.Printf("Token generated successfully for user: %s", username)
	return tokenString, nil
}

// RefreshToken реализует логику обновления токена.
func (s *UserServiceImpl) RefreshToken(token string) (string, error) {
	log.Printf("Attempting to refresh token...")

	claims := &jwt.RegisteredClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		// Проверяет метод подписи токена
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			log.Printf("Unexpected signing method: %s", t.Method.Alg())
			return nil, errors.New("unexpected signing method")
		}
		// Возвращает секретный ключ для проверки подписи
		return []byte(s.JWTSecret), nil
	})

	if err != nil {
		// Обрабатывает различные ошибки парсинга/валидации
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Println("Token is expired")
			return "", errors.New("token expired") // Специальная ошибка для истекшего токена
		}
		log.Printf("Error parsing token: %v", err)
		return "", errors.New("invalid token") // Общая ошибка для невалидного токена
	}

	if tkn.Valid {

		claimsMap, ok := tkn.Claims.(jwt.MapClaims)
		if !ok {
			log.Println("Invalid token claims format")
			return "", errors.New("invalid token claims: format is not MapClaims")
		}

		username, ok := claimsMap["sub"].(string)
		if !ok || username == "" {
			log.Printf("Token does not contain a valid subject.")
			return "", errors.New("invalid token claims: subject is not a string or is empty")
		}

		newToken, err := s.GenerateToken(username)
		if err != nil {
			log.Printf("Failed to generate new token: %v", err)
			return "", fmt.Errorf("failed to generate new token: %w", err)
		}
		log.Printf("Token refreshed successfully for user: %s", username)
		return newToken, nil
	}

	// Если токен невалиден после всех проверок
	log.Println("Token is not valid.")
	return "", errors.New("invalid token")
}
