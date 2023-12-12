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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
	"github.com/notapipeline/bwv/testdata"
)

func setupSuite(t *testing.T) func(t *testing.T) {
	t.Log("Setting up serve test suite")
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
    - 192.168.16.1
    - 192.168.16.4
  cert: cert.pem
  key: key.pem
  port: 8080
  apikeys:
    example.com: abcdef123456
    192.168.16.1: 2.MJZfa5JXC1DgB2KjQGIiKQ==|C6YSdz/i0K5hUQvp3cQWRw==|pQ7xH0FTfBQKx4Ij1EkG2EvHY/HDqIiDjCJ1USsjHnI=
`), 0644)

	if err != nil {
		t.Fatal(err)
	}

	return func(t *testing.T) {
		cache.Instance = osc
		config.ConfigPath = ocp
		cache.Reset()
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
					return "/tmp/fail.yaml"
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

			var (
				cnf *config.Config = config.New()
				err error
			)
			// Create a new instance of HttpServer
			server := NewHttpServer(cnf)

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
			expectedBody: `{"message":"bwv denied the request"}`,
			ipAddress:    "",
			token:        "",
			method:       "GET",
		},
		{
			name:         "fail if no ip address",
			expectedCode: http.StatusBadRequest,
			expectedBody: `{"message":"bwv denied the request"}`,
			ipAddress:    "",
			token:        "",
			method:       "POST",
		},
		{
			name:         "fail if no token",
			expectedCode: http.StatusUnauthorized,
			expectedBody: `{"message":"bwv denied the request"}`,
			ipAddress:    "127.0.0.1",
			token:        "",
			method:       "POST",
		},
		{
			name:         "invalid token",
			expectedCode: http.StatusForbidden,
			expectedBody: `{"message":"bwv denied the request"}`,
			ipAddress:    "192.168.0.1",
			token:        "invalidtoken",
			method:       "POST",
		},
		{
			name:         "broken token",
			expectedCode: http.StatusForbidden,
			expectedBody: "",
			ipAddress:    "192.168.16.8",
			token:        "2.MJZfa5JXC1DgB2KjQGIiKQ==|C6YSdz/i0K5UQvp3cQWRw=|pQ7xH0FTfBQKx4Ij1EkG2EvHY/HDqIiDjCJ1USsjHnI=",
			method:       "POST",
		},
		{
			name:         "token already exists",
			expectedCode: http.StatusBadRequest,
			expectedBody: "",
			ipAddress:    "192.168.16.1",
			token:        "2.MJZfa5JXC1DgB2KjQGIiKQ==|C6YSdz/i0K5hUQvp3cQWRw==|pQ7xH0FTfBQKx4Ij1EkG2EvHY/HDqIiDjCJ1USsjHnI=",
			method:       "POST",
		},
		{
			name:         "success",
			expectedCode: http.StatusOK,
			expectedBody: "",
			ipAddress:    "192.168.16.4",
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

			var cnf *config.Config = config.New()

			// Create a new instance of HttpServer
			server := NewHttpServer(cnf)
			if err = server.config.Load(config.ConfigModeServer); err != nil {
				t.Fatal(err)
			}

			server.Bwv.Secrets, err = cache.Instance("masterpw", "email@example.com", pbkdf)
			if err != nil {
				t.Fatal(err)
			}

			if err := cs.UnmarshalText([]byte(encryptedMasterPassword)); err != nil {
				t.Errorf("Expected nil error but got %v when unmarshalling master password to CipherString", err)
			}

			if err := server.Bwv.Secrets.Unlock(cs); err != nil {
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
	mocks := func() {
		testData := testdata.New()
		transport.DefaultHttpClient = &transport.MockHttpClient{
			Responses: []transport.MockHttpResponse{
				{
					Code: http.StatusOK,
					Body: testData.LoginResponse,
				},
				{
					Code: http.StatusOK,
					Body: testData.SyncResponse,
				},
				{
					Code: http.StatusOK,
					Body: testData.SyncResponse,
				},
				{
					Code: http.StatusOK,
					Body: testData.AttachmentLookupResponse,
				},
				{
					Code: http.StatusOK,
					Body: testData.Attachment,
				},
			},
		}

		config.GetSecrets = func(v bool) map[string]string {
			return map[string]string{
				"BW_CLIENTID":     "mockid",
				"BW_CLIENTSECRET": "mocktoken",
				"BW_PASSWORD":     "masterpw",
				"BW_EMAIL":        "email@example.com",
			}
		}
	}

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
			expectedBody: `{"message":"bwv denied the request - invalid method"}`,
			ipAddress:    "",
			token:        "",
			method:       "POST",
			path:         "/",
		},
		{
			name:         "fail if no ip address",
			expectedCode: http.StatusBadRequest,
			expectedBody: `{"message":"bwv denied the request"}`,
			ipAddress:    "",
			token:        "",
			method:       "GET",
			path:         "/",
		},
		{
			name: "fail if unmatched in whitelist",
			mocks: func() {
				testData := testdata.New()
				transport.DefaultHttpClient = &transport.MockHttpClient{
					Responses: []transport.MockHttpResponse{
						{
							Code: http.StatusOK,
							Body: []byte(`{"kdf":0, "kdfIterations": 800000}`),
						},
						{
							Code: http.StatusOK,
							Body: testData.LoginResponse,
						},
						{
							Code: http.StatusOK,
							Body: testData.SyncResponse,
						},
					},
				}
				config.GetSecrets = func(v bool) map[string]string {
					return map[string]string{
						"BW_PASSWORD": "masterpw",
						"BW_EMAIL":    "email@example.com",
					}
				}
			},
			expectedCode: http.StatusForbidden,
			expectedBody: `{"message":"bwv denied the request"}`,
			ipAddress:    "192.168.0.1",
			token:        "",
			method:       "GET",
			path:         "/",
		},
		{
			name:         "fail if no token",
			expectedCode: http.StatusUnauthorized,
			expectedBody: `{"message":"bwv denied the request"}`,
			ipAddress:    "127.0.0.1",
			token:        "",
			method:       "GET",
			path:         "/",
		},
		{
			name:         "end to end success full secret response",
			mocks:        mocks,
			expectedCode: http.StatusOK,
			expectedBody: `{"message":[{` +
				`"type":1,"id":"7501cb8e-2adc-4941-9758-8b09b95637ac",` +
				`"revision_date":"2022-10-01T18:15:30.6666667Z",` +
				`"name":"testkey","fields":{"example":"value"},` +
				`"folder_id":"79477330-c18a-42e5-aad5-9e9f1327b355",` +
				`"username":"testuser","password":"password","attachments":{}}]}`,
			ipAddress: "127.0.0.1",
			token:     "2.A35Y1GDMK6Q6QBFQ735qqw==|xDHKiep/RKP7Le05kZr/LA==|BksHlZe9hbFGSfcZDo+4exuiUBmXq+19rhkiTT7QDXo=",
			method:    "GET",
			path:      "/mockfolder/testkey",
		},
		{
			name:         "end to end success single field response",
			mocks:        mocks,
			expectedCode: http.StatusOK,
			expectedBody: `{"message":{"value":"value"}}`,
			ipAddress:    "127.0.0.1",
			token:        "2.A35Y1GDMK6Q6QBFQ735qqw==|xDHKiep/RKP7Le05kZr/LA==|BksHlZe9hbFGSfcZDo+4exuiUBmXq+19rhkiTT7QDXo=",
			method:       "GET",
			path:         "/mockfolder/testkey?fields=example",
		},
		{
			name:         "end to end success single property response",
			mocks:        mocks,
			expectedCode: http.StatusOK,
			expectedBody: `{"message":{"value":"testuser"}}`,
			ipAddress:    "127.0.0.1",
			token:        "2.A35Y1GDMK6Q6QBFQ735qqw==|xDHKiep/RKP7Le05kZr/LA==|BksHlZe9hbFGSfcZDo+4exuiUBmXq+19rhkiTT7QDXo=",
			method:       "GET",
			path:         "/mockfolder/testkey?properties=username",
		},
		{
			name:         "end to end success mixed fields and properties response",
			mocks:        mocks,
			expectedCode: http.StatusOK,
			expectedBody: `{"message":{"example":"value","password":"password","username":"testuser"}}`,
			ipAddress:    "127.0.0.1",
			token:        "2.A35Y1GDMK6Q6QBFQ735qqw==|xDHKiep/RKP7Le05kZr/LA==|BksHlZe9hbFGSfcZDo+4exuiUBmXq+19rhkiTT7QDXo=",
			method:       "GET",
			path:         "/mockfolder/testkey?fields=example&properties=username,password",
		},
		{
			name:         "end to end success attachment response",
			mocks:        mocks,
			expectedCode: http.StatusOK,
			expectedBody: `{"message":{"value":"` + base64.StdEncoding.EncodeToString(testdata.New().AttachmentDecrypted) + `"}}`,
			ipAddress:    "127.0.0.1",
			token:        "2.A35Y1GDMK6Q6QBFQ735qqw==|xDHKiep/RKP7Le05kZr/LA==|BksHlZe9hbFGSfcZDo+4exuiUBmXq+19rhkiTT7QDXo=",
			method:       "GET",
			path:         "/mockfolder/some-cipher-with-attachment?attachments=filename.unc",
		},
		{
			name:         "path failure",
			mocks:        mocks,
			expectedCode: http.StatusNotFound,
			expectedBody: `{"message":"Path 'nothing' not found"}`,
			ipAddress:    "127.0.0.1",
			token:        "2.A35Y1GDMK6Q6QBFQ735qqw==|xDHKiep/RKP7Le05kZr/LA==|BksHlZe9hbFGSfcZDo+4exuiUBmXq+19rhkiTT7QDXo=",
			method:       "GET",
			path:         "/nothing",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)
			var err error

			t.Log("Running mocks")
			if test.mocks != nil {
				test.mocks()
			}

			var cnf *config.Config = config.New()
			if err = cnf.Load(config.ConfigModeServer); err != nil {
				t.Fatal(err)
			}
			server := NewHttpServer(cnf)

			if test.mocks != nil {
				server.Bwv.Setup()
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
		})
	}
}
