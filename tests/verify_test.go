package tests

import (
	"auth_test/internal/handler"
	"auth_test/internal/service"
	mocks "auth_test/tests/service"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
)

func TestAuthHandler_Verify(t *testing.T) {
	const testValidToken = "valid_jwt_token_123"
	const testRefreshedToken = "refreshed_jwt_token_456"

	tests := []struct {
		name                 string
		authHeader           string
		setupMock            func(mockService *mocks.MockUserService)
		expectedStatus       int
		expectedAuthHeader   string
		expectedBodyContains string
	}{
		{
			name:       "Success Verify and Refresh (token still valid)",
			authHeader: "Bearer " + testValidToken,
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateToken(testValidToken).
					Return("testuser", nil).
					Times(1)

				mockService.EXPECT().
					GenerateToken("testuser").
					Return(testRefreshedToken, nil).
					Times(1)
			},
			expectedStatus:     http.StatusOK,
			expectedAuthHeader: "Bearer " + testRefreshedToken,
		},
		{
			name:       "Token Expired",
			authHeader: "Bearer expired_token_789",
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateToken("expired_token_789").
					Return("", service.ErrTokenExpired).
					Times(1)

				mockService.EXPECT().
					RefreshToken("expired_token_789").
					Return(testRefreshedToken, nil).
					Times(1)
			},
			expectedStatus:     http.StatusOK,
			expectedAuthHeader: "Bearer " + testRefreshedToken,
		},
		{
			name:       "Token Expired and Refresh Failed",
			authHeader: "Bearer expired_token_789",
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateToken("expired_token_789").
					Return("", service.ErrTokenExpired).
					Times(1)

				mockService.EXPECT().
					RefreshToken("expired_token_789").
					Return("", errors.New("refresh failed")).
					Times(1)
			},
			expectedStatus:       http.StatusInternalServerError,
			expectedBodyContains: "Internal server error during token refresh",
		},
		{
			name:       "Invalid Token Format or Signature",
			authHeader: "Bearer invalid_token_format",
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateToken("invalid_token_format").
					Return("", errors.New("invalid token format or signature")).
					Times(1)
			},
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Invalid token",
		},
		{
			name:       "Invalid Token Claims",
			authHeader: "Bearer invalid_claims_token",
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateToken("invalid_claims_token").
					Return("", errors.New("invalid token claims format")).
					Times(1)
			},
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Invalid token", // <-- ИЗМЕНЕНО: Ожидаем "Invalid token"
		},
		{
			name:                 "Missing Authorization Header",
			authHeader:           "",
			setupMock:            func(mockService *mocks.MockUserService) {},
			expectedStatus:       http.StatusBadRequest,
			expectedBodyContains: "Authorization header missing or malformed",
		},
		{
			name:                 "Malformed Authorization Header",
			authHeader:           "Basic invalid_header",
			setupMock:            func(mockService *mocks.MockUserService) {},
			expectedStatus:       http.StatusBadRequest,
			expectedBodyContains: "Invalid Authorization header format",
		},
		{
			name:       "Service Error on Token Generation (after successful validation)",
			authHeader: "Bearer valid_jwt_token_123",
			setupMock: func(mockService *mocks.MockUserService) {
				mockService.EXPECT().
					ValidateToken("valid_jwt_token_123").
					Return("testuser", nil).
					Times(1)

				mockService.EXPECT().
					GenerateToken("testuser").
					Return("", errors.New("signing error")).
					Times(1)
			},
			expectedStatus:       http.StatusInternalServerError,
			expectedBodyContains: "Internal server error generating new token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockService := mocks.NewMockUserService(ctrl)
			authHandler := handler.NewAuthHandler(mockService)

			tt.setupMock(mockService)

			req := httptest.NewRequest(http.MethodPost, "/verify", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			authHandler.Verify(rr, req)

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
