package bitw

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

func TestPrelogin(t *testing.T) {
	// Mock the HTTP client
	transport.DefaultHttpClient = MockPreloginSuccessHttpClient{}

	// Mock the cache.Instance function
	cache.Instance = func(password, email string, pbkdf types.KDFInfo) (*cache.SecretCache, error) {
		return &cache.SecretCache{
			KDF: pbkdf,
		}, nil
	}

	// Set up the preLoginRequest and expected response
	// Set up the expected hashed password
	expectedHashedPassword := "0GA3u/K3oddElx6cM1ztGEz4RI97+wBWflDkI4CRfsE="

	// Call the Prelogin function
	hashedPassword, err := Prelogin("password", "test@example.com")

	// Verify the result
	if err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	if hashedPassword != expectedHashedPassword {
		t.Errorf("Expected %q but got %q", expectedHashedPassword, hashedPassword)
	}
}

func TestPreloginFailsOnCreateSecretCache(t *testing.T) {
	// Mock the HTTP client
	transport.DefaultHttpClient = MockPreloginSuccessHttpClient{}

	// Mock the cache.Instance function
	cache.Instance = func(password, email string, pbkdf types.KDFInfo) (*cache.SecretCache, error) {
		return nil, fmt.Errorf("Could not create secret cache")
	}

	// Call the Prelogin function
	_, err := Prelogin("password", "test@example.com")

	// Verify the result
	if err == nil {
		t.Errorf("Expected error but got nil")
	}
}

func TestPreFailsOnPostlogin(t *testing.T) {
	// Mock the HTTP client
	transport.DefaultHttpClient = MockPreloginPostFailureHttpClient{}

	// Mock the cache.Instance function
	cache.Instance = func(password, email string, pbkdf types.KDFInfo) (*cache.SecretCache, error) {
		return &cache.SecretCache{
			KDF: pbkdf,
		}, nil
	}

	// Call the Prelogin function
	_, err := Prelogin("password", "test@example.com")

	// Verify the result
	if err == nil {
		t.Errorf("Expected error but got")
	}

}

type MockPreloginPostFailureHttpClient struct{}

func (m MockPreloginPostFailureHttpClient) Get(ctx context.Context, url string, resp any) error {
	return nil
}

func (m MockPreloginPostFailureHttpClient) DoWithBackoff(ctx context.Context, req *http.Request, response any) error {
	return nil
}

func (m MockPreloginPostFailureHttpClient) Post(ctx context.Context, url string, recv, send any) error {
	return fmt.Errorf("Post failed")
}

// MockHttpClient is a mock implementation of the HTTP client
type MockPreloginSuccessHttpClient struct{}

func (m MockPreloginSuccessHttpClient) Get(ctx context.Context, url string, resp any) error {
	return nil
}

func (m MockPreloginSuccessHttpClient) DoWithBackoff(ctx context.Context, req *http.Request, response any) error {
	info := &types.KDFInfo{
		Type:        types.KDFTypePBKDF2,
		Iterations:  800000,
		Memory:      types.IntPtr(0),
		Parallelism: types.IntPtr(0),
	}
	*response.(*types.KDFInfo) = *info
	return nil
}

// Post is a mock implementation of the Post method
func (m MockPreloginSuccessHttpClient) Post(ctx context.Context, url string, recv, send any) error {
	return m.DoWithBackoff(ctx, &http.Request{}, recv)
}
