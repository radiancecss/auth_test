package configs

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	//  Параметры веб-сервера
	ListenAddr string
	DebugMode  bool

	//  Параметры JWT
	JWTSecret            string
	JWTExpirationMinutes int

	//  Параметры базы данных
	DBHost     string // Хост базы данных
	DBPort     int    // Порт базы данных
	DBUser     string // Пользователь базы данных
	DBPassword string // Пароль для пользователя
	DBName     string // Название базы данных
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		// Значения по умолчанию
		ListenAddr:           ":8080",
		DBHost:               "localhost",
		DBPort:               5432,
		DebugMode:            false,
		JWTExpirationMinutes: 60, // Время жизни токена в минутах
	}

	//  Чтение обязательных переменных

	// JWTSecret - обязательная переменная.
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("environment variable JWT_SECRET is not set")
	}
	cfg.JWTSecret = jwtSecret

	// Параметры БД
	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		return nil, fmt.Errorf("environment variable DB_USER is not set")
	}
	cfg.DBUser = dbUser

	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		return nil, fmt.Errorf("environment variable DB_PASSWORD is not set")
	}
	cfg.DBPassword = dbPassword

	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		return nil, fmt.Errorf("environment variable DB_NAME is not set")
	}
	cfg.DBName = dbName

	//  Чтение необязательных переменных

	if addr := os.Getenv("LISTEN_ADDR"); addr != "" {
		cfg.ListenAddr = addr
	}

	if host := os.Getenv("DB_HOST"); host != "" {
		cfg.DBHost = host
	}

	if portStr := os.Getenv("DB_PORT"); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DB_PORT '%s': %w", portStr, err)
		}
		cfg.DBPort = port
	}

	if debugStr := os.Getenv("DEBUG_MODE"); debugStr != "" {
		debug, err := strconv.ParseBool(debugStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DEBUG_MODE '%s': %w", debugStr, err)
		}
		cfg.DebugMode = debug
	}

	if expMinStr := os.Getenv("JWT_EXPIRATION_MINUTES"); expMinStr != "" {
		expMin, err := strconv.Atoi(expMinStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWT_EXPIRATION_MINUTES '%s': %w", expMinStr, err)
		}
		if expMin <= 0 {
			return nil, fmt.Errorf("JWT_EXPIRATION_MINUTES must be a positive number")
		}
		cfg.JWTExpirationMinutes = expMin
	}

	return cfg, nil
}
