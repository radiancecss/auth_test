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

func (s *UserServiceImpl) ValidateCredentials(username, password string) (bool, error) {
	log.Printf("Validating credentials for user: %s", username)

	user, err := s.UserStore.Get(username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			log.Println("User not found.")
			return false, ErrInvalidCredentials
		}
		log.Printf("Error accessing user store: %v", err)
		return false, fmt.Errorf("failed to retrieve user: %w", err)
	}

	err = bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Println("Password mismatch.")
			return false, ErrInvalidCredentials
		}
		log.Printf("Error comparing password hash: %v", err)
		return false, fmt.Errorf("failed to compare password: %w", err)
	}

	log.Printf("Credentials are valid for user: %s", username)
	return true, nil
}

func (s *UserServiceImpl) GenerateToken(username string) (string, error) {
	log.Printf("Generating token for user: %s", username)

	expirationTime := time.Now().Add(s.TokenLifetime)

	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(s.JWTSecret))
	if err != nil {
		log.Printf("Error signing token: %v", err)
		return "", errors.New("failed to generate token")
	}

	log.Printf("Token generated successfully for user: %s", username)
	return tokenString, nil
}

func (s *UserServiceImpl) RefreshToken(refreshToken string) (string, error) {
	log.Printf("Attempting to refresh token...")

	claims := &jwt.RegisteredClaims{}
	tkn, err := jwt.ParseWithClaims(refreshToken, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("Unexpected signing method: %s", t.Header["alg"])
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.JWTSecret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Println("Token is expired")
			return "", ErrTokenExpired
		}
		log.Printf("Error parsing token: %v", err)
		return "", errors.New("invalid token")
	}

	if !tkn.Valid {
		log.Println("Token is not valid.")
		return "", errors.New("invalid token")
	}

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

	newAccessToken, err := s.GenerateToken(username)
	if err != nil {
		log.Printf("Failed to generate new token: %v", err)
		return "", fmt.Errorf("failed to generate new token: %w", err)
	}
	log.Printf("Token refreshed successfully for user: %s", username)
	return newAccessToken, nil
}

// ValidateToken проверяет JWT-токен и возвращает имя пользователя, если он валиден.
func (s *UserServiceImpl) ValidateToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.JWTSecret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrTokenExpired
		}
		return "", errors.New("invalid token format or signature")
	}

	if !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims format")
	}

	username, ok := claims["sub"].(string)
	if !ok || username == "" {
		return "", errors.New("invalid token: subject (username) not found")
	}

	return username, nil
}
