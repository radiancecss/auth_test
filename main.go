package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth_test/internal/config"  // Для загрузки конфигурации
	"auth_test/internal/handler" // Для HTTP-обработчиков
	"auth_test/internal/service" // Для бизнес-логики
	"auth_test/internal/store"   // Для хранилища данных
)

func main() {

	cfg := config.Config{
		ServerPort:        "8080",
		JWTSecret:         "secret_key_for_testing",
		TokenLifetimeMins: 60,
	}
	log.Printf("Configuration loaded: Port=%s, TokenLifetime=%d mins", cfg.ServerPort, cfg.TokenLifetimeMins)

	// 2. Инициализация зависимостей

	// 2.1. UserStore
	userStore := store.NewInMemoryUserStore() // Используем in-memory заглушку
	log.Println("UserStore (in-memory) initialized.")

	// 2.2. UserService
	userService := service.NewUserServiceImpl(userStore, cfg.JWTSecret, cfg.TokenLifetimeMins)
	log.Println("UserService initialized.")

	// 2.3. AuthHandler
	authHandler := handler.NewAuthHandler(userService)
	log.Println("AuthHandler initialized.")

	// 3. Настройка HTTP-маршрутов
	mux := http.NewServeMux()
	mux.HandleFunc("/login", authHandler.Login)
	mux.HandleFunc("/refresh", authHandler.Refresh) // Это будет наш verify endpoint из этапа 5
	log.Println("HTTP routes registered: /login, /refresh")

	// 4. Настройка HTTP-сервера
	server := &http.Server{
		Addr:         ":" + cfg.ServerPort, // Адрес сервера (например, ":8080")
		Handler:      mux,                  // маршрутизатор
		ReadTimeout:  10 * time.Second,     // Таймаут чтения запроса
		WriteTimeout: 10 * time.Second,     // Таймаут записи ответа
		IdleTimeout:  120 * time.Second,    // Таймаут неактивного соединения
	}

	go func() {
		log.Printf("Starting HTTP server on %s...", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
		log.Println("HTTP server stopped.")
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop

	log.Println("Shutting down HTTP server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Таймаут на завершение
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("HTTP server Shutdown: %v", err)
	}
	log.Println("HTTP server gracefully stopped.")
}
