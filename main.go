package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth_test/internal/config"
	"auth_test/internal/handler"
	"auth_test/internal/service"
	"auth_test/internal/store"
)

func main() {

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Printf("Configuration loaded: Port=%s, TokenLifetime=%d mins", cfg.ServerPort, cfg.TokenLifetimeMins)

	userStore := store.NewInMemoryUserStore()
	log.Println("UserStore (in-memory) initialized.")

	userService := service.NewUserServiceImpl(userStore, cfg.JWTSecret, cfg.TokenLifetimeMins)
	log.Println("UserService initialized.")

	authHandler := handler.NewAuthHandler(userService)
	log.Println("AuthHandler initialized.")

	verifyHandler := handler.NewVerifyHandler(userService)
	log.Println("VerifyHandler initialized.")

	mux := http.NewServeMux()
	mux.HandleFunc("/login", authHandler.Login)
	mux.HandleFunc("/refresh", authHandler.Refresh)

	mux.HandleFunc("/verify", verifyHandler.HandleVerify)
	log.Println("HTTP routes registered: /login, /refresh, /verify")

	server := &http.Server{
		Addr:         ":" + cfg.ServerPort,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("HTTP server Shutdown: %v", err)
	}
	log.Println("HTTP server gracefully stopped.")
}
