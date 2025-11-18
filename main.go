package main

import (
	"auth_test/internal/handler"
	"auth_test/internal/service"
	"auth_test/internal/store"
	"log"
	"net/http"
)

func main() {
	// Создаем хранилище пользователей
	userStore := store.NewInMemoryUserStore()

	// Создаем сервис пользователей
	userService := service.NewUserServiceImpl(userStore, "your_jwt_secret", 60)

	// Создаем обработчик
	authHandler := handler.NewAuthHandler(userService)

	// Регистрируем маршруты
	http.HandleFunc("/login", authHandler.Login)             // Маршрут для авторизации
	http.HandleFunc("/profile", authHandler.ProfileHandler)  // Защищенный маршрут для профиля
	http.HandleFunc("/add-user", authHandler.AddUserHandler) // Добавление пользователя

	// Запускаем сервер
	log.Println("Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
