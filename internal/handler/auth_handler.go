package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"auth_test/internal/service"

	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	userService service.UserService
}

func NewAuthHandler(userService service.UserService) *AuthHandler {
	return &AuthHandler{
		userService: userService,
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "basic" {
		http.Error(w, "Authorization header malformed", http.StatusUnauthorized)
		return
	}

	credentials, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(w, "Failed to decode credentials", http.StatusUnauthorized)
		return
	}

	loginParts := strings.SplitN(string(credentials), ":", 2)
	if len(loginParts) != 2 {
		http.Error(w, "Invalid username or password format", http.StatusUnauthorized)
		return
	}
	username := loginParts[0]
	password := loginParts[1]

	isValid, err := h.userService.ValidateCredentials(username, password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) || errors.Is(err, service.ErrUserNotFound) {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal server error during login validation", http.StatusInternalServerError)
		return
	}

	if !isValid {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := h.userService.GenerateToken(username)
	if err != nil {
		http.Error(w, "Internal server error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+token)
	w.WriteHeader(http.StatusOK)
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

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
		if errors.Is(err, jwt.ErrTokenExpired) { // <-- Здесь мог быть jwt.ErrTokenExpired, если он используется напрямую
			http.Error(w, "Token expired", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error refreshing token", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Authorization", "Bearer "+newToken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token refreshed successfully"))
}

// Verify проверяет JWT-токен и обновляет его, если он валиден.
func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header missing or malformed", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusBadRequest)
		return
	}
	tokenString := parts[1]

	username, err := h.userService.ValidateToken(tokenString)
	if err != nil {
		if errors.Is(err, service.ErrTokenExpired) {
			refreshedToken, refreshErr := h.userService.RefreshToken(tokenString)
			if refreshErr != nil {
				if errors.Is(refreshErr, service.ErrTokenExpired) {
					http.Error(w, "Token expired and cannot be refreshed", http.StatusUnauthorized)
				} else {
					http.Error(w, "Internal server error during token refresh", http.StatusInternalServerError)
				}
				return
			}
			w.Header().Set("Authorization", "Bearer "+refreshedToken)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Token expired, but refreshed successfully"))
			return
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	}

	newToken, err := h.userService.GenerateToken(username)
	if err != nil {
		http.Error(w, "Internal server error generating new token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+newToken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token verified"))
}
