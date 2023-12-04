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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/types"
)

func setupSuite(t *testing.T) func(t *testing.T) {
	t.Log("Setting up config suite")
	tempDir := t.TempDir()
	ocp := config.ConfigPath
	osc := cache.Instance

	config.ConfigPath = func(m config.ConfigMode) string {
		return filepath.Join(tempDir, "server.yaml")
	}
	err := os.WriteFile(config.ConfigPath(config.ConfigModeServer), []byte(`
server:
  whitelist:
    - 127.0.0.0/24
  cert: cert.pem
  key: key.pem
  port: 8080
  apikeys:
    example.com: abcdef123456
`), 0644)

	if err != nil {
		t.Fatal(err)
	}

	return func(t *testing.T) {
		cache.Instance = osc
		config.ConfigPath = ocp
	}
}

func TestHttpServerReload(t *testing.T) {
	tests := []struct {
		name          string
		expectedCode  int
		expectedBody  string
		expectedError error
		mocks         func()
	}{
		{
			name:          "success",
			expectedCode:  http.StatusNoContent,
			expectedBody:  "",
			expectedError: nil,
		},
		{
			name:          "failed to load config",
			expectedCode:  http.StatusInternalServerError,
			expectedBody:  `{"message":"an internal server error has occurred - please try again later"}`,
			expectedError: nil,
			mocks: func() {
				// Mock the config
				config.ConfigPath = func(m config.ConfigMode) string {
					return "/tmp"
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)

			if test.mocks != nil {
				test.mocks()
			}

			// Create a new instance of HttpServer
			server := NewHttpServer()

			// Create a new request
			req, err := http.NewRequest("GET", "/reload", nil)
			if err != nil {
				t.Fatal(err)
			}

			// Create a new response recorder
			recorder := httptest.NewRecorder()

			// Call the reload method
			server.reload(recorder, req)

			// Check the response status code
			if recorder.Code != test.expectedCode {
				t.Errorf("Expected status code %d, got %d", test.expectedCode, recorder.Code)
			}

			// Check the response body
			if test.expectedBody != "" {
				actualBody := recorder.Body.String()
				if actualBody != test.expectedBody {
					t.Errorf("Expected response body %q, got %q", test.expectedBody, actualBody)
				}
			}
		})
	}
}

func TestStoreToken(t *testing.T) {
	tests := []struct {
		name         string
		expectedCode int
		expectedBody string
		mocks        func()
		ipAddress    string
		token        string
		method       string
	}{
		{
			name:         "Fail if invalid method",
			expectedCode: http.StatusMethodNotAllowed,
			expectedBody: `{"message":"bwv denied storeToken request - invalid method"}`,
			ipAddress:    "",
			token:        "",
			method:       "GET",
		},
		{
			name:         "fail if no ip address",
			expectedCode: http.StatusBadRequest,
			expectedBody: `{"message":"bwv denied storeToken request - no ip address"}`,
			ipAddress:    "",
			token:        "",
			method:       "POST",
		},
		{
			name:         "fail if no token",
			expectedCode: http.StatusUnauthorized,
			expectedBody: `{"message":"bwv denied storeToken request - missing or invalid token"}`,
			ipAddress:    "192.168.0.1",
			token:        "",
			method:       "POST",
		},
		{
			name:         "invalid token",
			expectedCode: http.StatusForbidden,
			expectedBody: `{"message":"bwv denied storeToken request from ip 192.168.0.1 - could not unmarshal token: cipher string does not contain type: invalidtoken"}`,
			mocks: func() {
				_, err := cache.Instance("masterpw", "email@example.com", types.KDFInfo{
					Type:       types.KDFTypePBKDF2,
					Iterations: 800000,
				})
				if err != nil {
					t.Fatal(err)
				}
			},
			ipAddress: "192.168.0.1",
			token:     "invalidtoken",
			method:    "POST",
		},
		{
			name:         "success",
			expectedCode: http.StatusOK,
			expectedBody: "",
			ipAddress:    "192.168.0.1",
			token:        "2.MJZfa5JXC1DgB2KjQGIiKQ==|C6YSdz/i0K5hUQvp3cQWRw==|pQ7xH0FTfBQKx4Ij1EkG2EvHY/HDqIiDjCJ1USsjHnI=",
			method:       "POST",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)

			var (
				err                     error
				cs                      types.CipherString
				encryptedMasterPassword string = "2.i/7aEu9Pc3WI8hvaADB/Fg==|" +
					"gFxSM2jOaUbJpfYharUTX/OEEnUHSwDoLEZKXt1bAAxAhZpxaj8zE/" +
					"19tiC7o12BRwPpydQb7bjmGDIG8unMNpt9rL29N83qY8tmfQCtMeA=|" +
					"uhT83UtbUx8Ls2NYHFUh8ny5a4vdAObg/7aLWJeYtH4="
				pbkdf types.KDFInfo = types.KDFInfo{
					Type:        types.KDFTypePBKDF2,
					Iterations:  800000,
					Memory:      types.IntPtr(0),
					Parallelism: types.IntPtr(0),
				}
			)

			if test.mocks != nil {
				test.mocks()
				if _, err = crypto.ClientEncrypt("masterpw", "email@example.com", "invalidtoken", pbkdf); err != nil {
					t.Fatal(err)
					return
				}
			}

			// Create a new instance of HttpServer
			server := NewHttpServer()
			if err = server.c.Load(config.ConfigModeServer); err != nil {
				t.Fatal(err)
			}

			var c *cache.SecretCache
			c, err = cache.Instance("masterpw", "email@example.com", pbkdf)
			if err != nil {
				t.Fatal(err)
			}

			if err := cs.UnmarshalText([]byte(encryptedMasterPassword)); err != nil {
				t.Errorf("Expected nil error but got %v when unmarshalling master password to CipherString", err)
			}

			if err := c.Unlock(cs); err != nil {
				t.Errorf("Expected nil error but got %v when unlocking", err)
			}

			// Create a new request
			req, err := http.NewRequest(test.method, "/storetoken", nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.ipAddress != "" {
				req.RemoteAddr = test.ipAddress
			}

			if test.token != "" {
				req.Header.Set("Authorization", "Bearer "+test.token)
			}

			// Create a new response recorder
			recorder := httptest.NewRecorder()

			// Call the reload method
			server.storeToken(recorder, req)

			// Check the response status code
			if recorder.Code != test.expectedCode {
				t.Errorf("Expected status code %d, got %d", test.expectedCode, recorder.Code)
			}

			// Check the response body
			if test.expectedBody != "" {
				actualBody := recorder.Body.String()
				if actualBody != test.expectedBody {
					t.Errorf("Expected response body %q, got %q", test.expectedBody, actualBody)
				}
			}

			if test.expectedCode == http.StatusOK {
				m := make(map[string]string)
				_ = json.Unmarshal(recorder.Body.Bytes(), &m)
				if _, ok := m["token"]; !ok {
					t.Errorf("Expected token in response body")
				}
			}
		})
	}
}

func TestGetPath(t *testing.T) {
	tests := []struct {
		name         string
		expectedCode int
		expectedBody string
		mocks        func()
		ipAddress    string
		token        string
		method       string
		path         string
	}{
		{
			name:         "Fail if invalid method",
			expectedCode: http.StatusMethodNotAllowed,
			expectedBody: `{"message":"bwv denied get request - invalid method"}`,
			ipAddress:    "",
			token:        "",
			method:       "POST",
			path:         "/",
		},
		{
			name:         "fail if no ip address",
			expectedCode: http.StatusBadRequest,
			expectedBody: `{"message":"bwv denied get request - no ip address"}`,
			ipAddress:    "",
			token:        "",
			method:       "GET",
			path:         "/",
		},
		{
			name:         "fail if unmatched in whitelist",
			expectedCode: http.StatusForbidden,
			expectedBody: `{"message":"bwv denied get request"}`,
			ipAddress:    "192.168.0.1",
			token:        "",
			method:       "GET",
			path:         "/",
		},
		{
			name:         "fail if no token",
			expectedCode: http.StatusUnauthorized,
			expectedBody: `{"message":"bwv denied get request - missing or invalid token"}`,
			ipAddress:    "127.0.0.1",
			token:        "",
			method:       "GET",
			path:         "/",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)
			var (
				err                     error
				cs                      types.CipherString
				encryptedMasterPassword string = "2.i/7aEu9Pc3WI8hvaADB/Fg==|" +
					"gFxSM2jOaUbJpfYharUTX/OEEnUHSwDoLEZKXt1bAAxAhZpxaj8zE/" +
					"19tiC7o12BRwPpydQb7bjmGDIG8unMNpt9rL29N83qY8tmfQCtMeA=|" +
					"uhT83UtbUx8Ls2NYHFUh8ny5a4vdAObg/7aLWJeYtH4="
				pbkdf types.KDFInfo = types.KDFInfo{
					Type:        types.KDFTypePBKDF2,
					Iterations:  800000,
					Memory:      types.IntPtr(0),
					Parallelism: types.IntPtr(0),
				}
			)

			if test.mocks != nil {
				test.mocks()
				if _, err = crypto.ClientEncrypt("masterpw", "email@example.com", "invalidtoken", pbkdf); err != nil {
					t.Fatal(err)
					return
				}
			}

			// Create a new instance of HttpServer
			server := NewHttpServer()
			if err = server.c.Load(config.ConfigModeServer); err != nil {
				t.Fatal(err)
			}

			var c *cache.SecretCache
			c, err = cache.Instance("masterpw", "email@example.com", pbkdf)
			if err != nil {
				t.Fatal(err)
			}

			if err := cs.UnmarshalText([]byte(encryptedMasterPassword)); err != nil {
				t.Errorf("Expected nil error but got %v when unmarshalling master password to CipherString", err)
			}

			if err := c.Unlock(cs); err != nil {
				t.Errorf("Expected nil error but got %v when unlocking", err)
			}

			// Create a new request
			req, err := http.NewRequest(test.method, test.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.ipAddress != "" {
				req.RemoteAddr = test.ipAddress
			}

			if test.token != "" {
				req.Header.Set("Authorization", "Bearer "+test.token)
			}

			// Create a new response recorder
			recorder := httptest.NewRecorder()

			// call the getPath method
			server.getPath(recorder, req)

			// Check the response status code
			if recorder.Code != test.expectedCode {
				t.Errorf("Expected status code %d, got %d", test.expectedCode, recorder.Code)
			}

			// Check the response body
			if test.expectedBody != "" {
				actualBody := recorder.Body.String()
				if actualBody != test.expectedBody {
					t.Errorf("Expected response body %q, got %q", test.expectedBody, actualBody)
				}
			}

			if test.expectedCode == http.StatusOK {
				m := make(map[string]string)
				_ = json.Unmarshal(recorder.Body.Bytes(), &m)
				if _, ok := m["token"]; !ok {
					t.Errorf("Expected token in response body")
				}
			}

		})
	}
}
