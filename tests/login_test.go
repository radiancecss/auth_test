package tests

import (
	"auth_test/internal/handler"
	"auth_test/internal/service"
	mocks "auth_test/tests/service" // <-- Импорт сгенерированного мока
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
)

func TestAuthHandler_Login(t *testing.T) {
	const testToken = "jwt_token_123"

	tests := []struct {
		name                 string
		authHeader           string
		setupMock            func(mockService *mocks.MockUserService)
		expectedStatus       int
		expectedAuthHeader   string
		expectedBodyContains string
	}{
		{
			name:       "Success Login",
			authHeader: "Basic dGVzdHVzZXI6cGFzc3dvcmQxMjM=", // testuser:password123
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateCredentials("testuser", "password123").
					Return(true, nil).
					Times(1)

				mockService.EXPECT().
					GenerateToken("testuser").
					Return(testToken, nil).
					Times(1)
			},
			expectedStatus:     http.StatusOK,
			expectedAuthHeader: "Bearer " + testToken,
		},
		{
			name:       "Invalid Credentials",
			authHeader: "Basic dGVzdHVzZXI6d3JvbmdwYXNzd29yZA==", // wrong password
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateCredentials("testuser", "wrongpassword").
					Return(false, service.ErrInvalidCredentials).
					Times(1)
			},
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Invalid username or password",
		},
		{
			name:                 "Malformed Basic Header",
			authHeader:           "Basic Zm9vYmFy",                            // Base64 для "foobar" (нет двоеточия)
			setupMock:            func(mockService *mocks.MockUserService) {}, // Мок не будет вызван
			expectedStatus:       http.StatusUnauthorized,                     // <-- Теперь 401, как возвращает ваш хендлер
			expectedBodyContains: "Invalid username or password format",       // <-- Соответствующее сообщение
		},
		{
			name:                 "Missing Authorization Header",
			authHeader:           "",
			setupMock:            func(mockService *mocks.MockUserService) {}, // Мок не будет вызван
			expectedStatus:       http.StatusUnauthorized,                     // <-- Теперь 401, как возвращает ваш хендлер
			expectedBodyContains: "Authorization header missing",              // <-- Соответствующее сообщение
		},
		{
			name:       "Service Error on Token Generation",
			authHeader: "Basic dGVzdHVzZXI6cGFzc3dvcmQxMjM=",
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateCredentials(gomock.Any(), gomock.Any()).
					Return(true, nil).
					Times(1)

				mockService.EXPECT().
					GenerateToken(gomock.Any()).
					Return("", errors.New("signing error")).
					Times(1)
			},
			expectedStatus:       http.StatusInternalServerError,
			expectedBodyContains: "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockService := mocks.NewMockUserService(ctrl)
			authHandler := handler.NewAuthHandler(mockService)

			tt.setupMock(mockService)

			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			authHandler.Login(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Fatalf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				token := rr.Header().Get("Authorization")
				if token != tt.expectedAuthHeader {
					t.Errorf("Expected Auth header '%s', got '%s'", tt.expectedAuthHeader, token)
				}
			}

			if tt.expectedBodyContains != "" && !strings.Contains(rr.Body.String(), tt.expectedBodyContains) {
				t.Errorf("Expected body to contain '%s', but got '%s'", tt.expectedBodyContains, rr.Body.String())
			}
		})
	}
}
