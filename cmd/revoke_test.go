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
package cmd

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

func TestRevokeCmd(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		address     string
		password    string
		kdf         types.KDFInfo
		expectedErr error
		getPassword func() ([]byte, error)
		responses   []transport.MockHttpResponse
	}{
		{
			name:        "test successful revoke",
			email:       "email@example.com",
			address:     "127.0.0.1",
			password:    "password",
			expectedErr: nil,
			getPassword: func() ([]byte, error) {
				return []byte("password"), nil
			},
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 200,
					Body: []byte(`{"statuscode": 200, "message":"Token revoked for address 127.0.0.1"}`),
				},
			},
		},
		{
			name:        "test invalid email",
			email:       "email",
			address:     "127.0.0.1",
			password:    "password",
			expectedErr: errors.New("invalid email address \"mail: missing '@' or angle-addr\""),
			getPassword: func() ([]byte, error) {
				return []byte("password"), nil
			},
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 0,
					Body: []byte(``),
				},
			},
		},
		{
			name:        "test invalid password",
			email:       "email@example.com",
			address:     "127.0.0.1",
			password:    "",
			expectedErr: errors.New("invalid password \"invalid password\""),
			getPassword: func() ([]byte, error) {
				return nil, errors.New("invalid password")
			},
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 0,
					Body: []byte(``),
				},
			},
		},
		{
			name:    "rate limited",
			address: "localhost",
			email:   "test@example.com",
			getPassword: func() ([]byte, error) {
				return nil, nil
			},
			expectedErr: errors.New(`unable to get kdf info: "Bad Request: ` +
				`{\"message\":\"Traffic from your network looks unusual. ` +
				`Connect to a different network or try again later. [Error Code 6]\"}"`),
			responses: []transport.MockHttpResponse{
				{
					Code: 400,
					Body: []byte(`{"message":"Traffic from your network looks unusual.` +
						` Connect to a different network or try again later. [Error Code 6]"}`),
				},
				{
					Code: 400,
					Body: []byte(`{"message":"Traffic from your network looks unusual.` +
						` Connect to a different network or try again later. [Error Code 6]"}`),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Mock getPassword function
			opwd := getPassword
			defer func() {
				getPassword = opwd
			}()
			getPassword = test.getPassword
			email = test.email
			address = test.address
			// Mock HTTP client
			transport.DefaultHttpClient = &transport.MockHttpClient{
				Responses: test.responses,
			}

			var buf bytes.Buffer
			log.SetOutput(&buf)
			of := fatal
			defer func() {
				fatal = of
				log.SetFlags(log.Flags() & (log.Ldate | log.Ltime))
			}()
			fatal = func(format string, v ...interface{}) {
				log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
				log.Printf(format, v...)
			}
			revokeCmd.Run(revokeCmd, []string{test.address, test.email})

			var actual string = strings.TrimSpace(buf.String())
			if test.expectedErr != nil {
				var expected string = strings.TrimSpace(test.expectedErr.Error())

				if expected != actual {
					t.Errorf("Expected log output %q, but got %q", expected, actual)
				}
				return
			}
			var msg string = "Token revoked for address 127.0.0.1"
			if !strings.Contains(buf.String(), msg) {
				t.Errorf("Expected log output to contain %q, but got %q", msg, buf.String())
			}
		})
	}
}
