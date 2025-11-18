package config

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	ListenAddr string
	JWTSecret  string
}

func LoadConfig() (*Config, error) {
	// Загружаем .env файл
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Загружаем конфигурацию с помощью Viper
	viper.AutomaticEnv() // автоматически ищет переменные окружения

	config := &Config{
		ListenAddr: viper.GetString("SERVER_PORT"), // Получаем порт сервера
		JWTSecret:  viper.GetString("JWT_SECRET"),  // Получаем секрет для JWT
	}

	return config, nil
}
