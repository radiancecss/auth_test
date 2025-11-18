package handler

import (
	"auth_test/internal/service"
	"encoding/json"
	"fmt"
	"net/http"
)

// Структура AuthHandler
type AuthHandler struct {
	userService service.UserService
}

// Конструктор AuthHandler
func NewAuthHandler(userService service.UserService) *AuthHandler {
	return &AuthHandler{userService: userService}
}

// AddUserHandler — обработчик для добавления нового пользователя
func (h *AuthHandler) AddUserHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	var user struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Декодируем тело запроса
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Некорректные данные", http.StatusBadRequest)
		return
	}

	// Добавляем пользователя в хранилище
	err = h.userService.AddUser(user.Username, user.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка при добавлении пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Возвращаем успешный ответ
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User added successfully"))
}

// Login для авторизации пользователя
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Получаем логин и пароль из BasicAuth
	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Проверка логина и пароля
	isValid, err := h.userService.ValidateCredentials(username, password)
	if err != nil || !isValid {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерация токенов
	accessToken, err := h.userService.GenerateToken(username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating token: %v", err), http.StatusInternalServerError)
		return
	}

	// Возвращаем токены
	tokens := map[string]string{
		"access_token": accessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tokens); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// ProfileHandler — защищенный эндпоинт для /profile
func (h *AuthHandler) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Извлекаем токен из заголовка Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Проверяем токен
	tokenString := authHeader[len("Bearer "):]
	username, err := h.userService.ValidateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Если токен валиден, возвращаем данные пользователя
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"message": "Welcome, %s"}`, username)))
}
