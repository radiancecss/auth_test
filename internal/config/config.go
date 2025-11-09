package config

import (
	"fmt"
	"log"
	"os"
	"strconv" // Для конвертации строки в int
)

type Config struct {
	ServerPort        string
	JWTSecret         string
	TokenLifetimeMins int
}

// LoadConfig читает конфигурации из переменных окружения.
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Чтение ServerPort
	port := os.Getenv("APP_PORT") // Или "ServerPort", если ты хочешь использовать такое имя переменной
	if port == "" {
		port = "8080" // Значение по умолчанию
		log.Printf("APP_PORT not set, using default: %s", port)
	}
	cfg.ServerPort = port

	// Чтение JWTSecret
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable not set. Cannot start application")
	}
	cfg.JWTSecret = jwtSecret

	// Чтение TokenLifetimeMins
	lifetimeStr := os.Getenv("JWT_TOKEN_LIFETIME_MINS")
	if lifetimeStr == "" {
		lifetimeStr = "60" // Значение по умолчанию
		log.Printf("JWT_TOKEN_LIFETIME_MINS not set, using default: %s", lifetimeStr)
	}
	lifetime, err := strconv.Atoi(lifetimeStr)
	if err != nil {
		
		return nil, fmt.Errorf("invalid JWT_TOKEN_LIFETIME_MINS: %v", err)
	}
	cfg.TokenLifetimeMins = lifetime

	log.Println("Configuration loaded successfully.")
	return cfg, nil
}
