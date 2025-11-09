package handler

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"auth_test/internal/service" // Путь к твоему сервису
)

// VerifyHandler обрабатывает запросы проверки JWT-токена.
type VerifyHandler struct {
	userService service.UserService
}

// NewVerifyHandler создает новый экземпляр VerifyHandler.
func NewVerifyHandler(userService service.UserService) *VerifyHandler {
	return &VerifyHandler{
		userService: userService,
	}
}

// HandleVerify обрабатывает HTTP-запрос для проверки JWT-токена.
func (h *VerifyHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	// Ожидаем только POST запросы для проверки токена
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Извлекаем токен из заголовка Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}

	// Токен должен быть в формате "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "Authorization header malformed", http.StatusUnauthorized)
		return
	}
	token := parts[1]

	// Валидируем токен через UserService
	username, err := h.userService.ValidateToken(token)
	if err != nil {
		// Обработка ошибок валидации токена
		if errors.Is(err, service.ErrTokenExpired) {
			http.Error(w, "Token expired", http.StatusUnauthorized)
		} else {

			http.Error(w, "Invalid token", http.StatusBadRequest)
		}
		return
	}

	newToken, err := h.userService.GenerateToken(username)
	if err != nil {
		log.Printf("Error generating new token after verification: %v", err)
		http.Error(w, "Internal server error generating new token", http.StatusInternalServerError)
		return
	}

	// Возвращаем новый токен в заголовке Authorization
	w.Header().Set("Authorization", "Bearer "+newToken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token verified and refreshed")) // Сообщение об успехе
}
