/*
 *   Copyright 2023 Martin Proffitt <mproffitt@choclab.net>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
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
	defer setupSuite(t)(t)
	// Mock the HTTP client
	transport.DefaultHttpClient = MockPreloginSuccessHttpClient{}

	// Mock the cache.Instance function
	cache.Instance = func(password, email []byte, pbkdf types.KDFInfo) (*cache.SecretCache, error) {
		return &cache.SecretCache{
			KDF: pbkdf,
		}, nil
	}
	cache.MasterPassword = func() ([]byte, error) {
		return []byte("password"), nil
	}

	// Set up the preLoginRequest and expected response
	// Set up the expected hashed password
	//expectedHashedPassword := "0GA3u/K3oddElx6cM1ztGEz4RI97+wBWflDkI4CRfsE="
	expectedHashedPassword := "soB7e/t+R1y//YFB6YabOea5QnZWeace0r3XXP5luE0="

	// Call the Prelogin function
	var b *Bwv = NewBwv()
	hashedPassword, err := b.prelogin([]byte("password"), []byte("test@example.com"))

	// Verify the result
	if err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	if hashedPassword != expectedHashedPassword {
		t.Errorf("Expected %q but got %q", expectedHashedPassword, hashedPassword)
	}
}

func TestPreloginFailsOnCreateSecretCache(t *testing.T) {
	defer setupSuite(t)(t)
	// Mock the HTTP client
	transport.DefaultHttpClient = MockPreloginSuccessHttpClient{}

	// Mock the cache.Instance function
	cache.Instance = func(password, email []byte, pbkdf types.KDFInfo) (*cache.SecretCache, error) {
		return nil, fmt.Errorf("Could not create secret cache")
	}

	var b *Bwv = NewBwv()
	// Call the Prelogin function
	_, err := b.prelogin([]byte("password"), []byte("test@example.com"))

	// Verify the result
	if err == nil {
		t.Errorf("Expected error but got nil")
	}
}

func TestPreFailsOnPostlogin(t *testing.T) {
	defer setupSuite(t)(t)
	// Mock the HTTP client
	transport.DefaultHttpClient = MockPreloginPostFailureHttpClient{}

	// Mock the cache.Instance function
	cache.Instance = func(password, email []byte, pbkdf types.KDFInfo) (*cache.SecretCache, error) {
		return &cache.SecretCache{
			KDF: pbkdf,
		}, nil
	}

	var b *Bwv = NewBwv()
	// Call the Prelogin function
	_, err := b.prelogin([]byte("password"), []byte("test@example.com"))

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
