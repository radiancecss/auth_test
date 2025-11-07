package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"auth_test/internal/service"

	"github.com/golang-jwt/jwt/v5"
)

// обрабатывает http запросы для аутентификации
type AuthHandler struct {
	userService service.UserService
}

// создает новый экземпляр authhandlera
func NewAuthHandler(userService service.UserService) *AuthHandler {
	return &AuthHandler{
		userService: userService,
	}
}

// структура для запроса
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	defer r.Body.Close()

	isValid, err := h.userService.ValidateCredentials(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) || errors.Is(err, service.ErrUserNotFound) {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal server error during login", http.StatusInternalServerError)
		return
	}

	if !isValid {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := h.userService.GenerateToken(req.Username)
	if err != nil {
		http.Error(w, "Internal server error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+token)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

// RefreshRequest структура для запроса обновления токена.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh обрабатывает POST /refresh.
// Принимает JSON с refresh_token.
// Возвращает 200 OK и Authorization: Bearer <new_token> при успехе.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	newToken, err := h.userService.RefreshToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			http.Error(w, "Token expired", http.StatusUnauthorized)
		} else if err != nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
		}
		http.Error(w, "Internal server error refreshing token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+newToken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token refreshed successfully"))
}
