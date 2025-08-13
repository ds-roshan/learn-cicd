package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key-123"},
			},
			expectedKey:   "test-api-key-123",
			expectedError: "",
		},
		{
			name: "valid API key with spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-api-key-with-spaces"},
			},
			expectedKey:   "my-api-key-with-spaces",
			expectedError: "",
		},
		{
			name: "valid API key with special characters",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123-def456_ghi789"},
			},
			expectedKey:   "abc123-def456_ghi789",
			expectedError: "",
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer test-token"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - wrong case",
			headers: http.Header{
				"Authorization": []string{"apikey test-api-key"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - only ApiKey without key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - empty key",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: "",
		},
		{
			name: "malformed header - no space between ApiKey and key",
			headers: http.Header{
				"Authorization": []string{"ApiKeytest-key"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "valid API key with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey   test-key-with-extra-spaces"},
			},
			expectedKey:   "",
			expectedError: "",
		},
		{
			name: "API key with multiple parts separated by spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey part1 part2 part3"},
			},
			expectedKey:   "part1",
			expectedError: "",
		},
		{
			name: "case sensitive - different header key case",
			headers: http.Header{
				"authorization": []string{"ApiKey test-key"},
			},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "API key with UUID format",
			headers: http.Header{
				"Authorization": []string{"ApiKey 550e8400-e29b-41d4-a716-446655440000"},
			},
			expectedKey:   "550e8400-e29b-41d4-a716-446655440000",
			expectedError: "",
		},
		{
			name: "very long API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890"},
			},
			expectedKey:   "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check the returned key
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}

			// Check the error
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, want %v", tt.expectedError)
				} else if err.Error() != tt.expectedError {
					t.Errorf("GetAPIKey() error = %v, want %v", err.Error(), tt.expectedError)
				}
			}
		})
	}
}
