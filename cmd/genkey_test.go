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
	"fmt"
	"log"
	"regexp"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/twpayne/go-pinentry"
)

func TestGenkeyCmd(t *testing.T) {
	tests := []struct {
		name        string
		addresses   []string
		email       string
		expectedErr error
		getPassword func() ([]byte, error)
		responses   []transport.MockHttpResponse
	}{
		{
			name: "no addresses assumes localhost",
			addresses: []string{
				"localhost",
			},
			email:       "test@example.com",
			expectedErr: nil,
			getPassword: func() ([]byte, error) {
				return []byte("password"), nil
			},
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":100000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 200,
					Body: []byte(`{"statuscode": 200, "message":"stored token for address localhost"}`),
				},
			},
		},
		{
			name:      "no email",
			addresses: []string{"localhost"},
			email:     "",
			getPassword: func() ([]byte, error) {
				return nil, nil
			},
			expectedErr: errors.New("invalid email address \"mail: no address\""),
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":100000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 0,
					Body: []byte(``),
				},
			},
		},
		{
			name:      "rate limited",
			addresses: []string{"localhost"},
			email:     "test@example.com",
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

			// Mock transport.DefaultHttpClient.DoWithBackoff function
			transport.DefaultHttpClient = &transport.MockHttpClient{
				Responses: test.responses,
			}
			// Capture log output
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

			genkeyCmd.Run(genkeyCmd, test.addresses)

			if test.expectedErr != nil {
				var (
					expected string = strings.TrimSpace(test.expectedErr.Error())
					actual   string = strings.TrimSpace(buf.String())
				)
				if expected != actual {
					t.Errorf("Expected log output %q, but got %q", expected, actual)
				}
				return
			}

			var re = regexp.MustCompile(`(?m).*\t[a-zA-Z0-9]{32}`)
			matches := re.FindAllString(buf.String(), -1)
			if len(matches) != len(test.addresses) {
				t.Errorf("Expected %d tokens, but got %d", len(test.addresses), len(matches))
			}
		})
	}
}
func TestGetPassword(t *testing.T) {
	tests := []struct {
		name             string
		expectedResult   string
		expectedErr      error
		mockClient       func(options ...pinentry.ClientOption) (c *pinentry.Client, err error)
		mockReadPassword func(prompt string) (password string, err error)
	}{
		{
			name:           "cancelled context",
			expectedResult: "",
			expectedErr:    fmt.Errorf("Cancelled"),
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				process := MockProcess{
					value:  "",
					status: true,
					readlnerr: &pinentry.AssuanError{
						Code: pinentry.AssuanErrorCodeCancelled,
					},
					lines: []struct {
						line []byte
						err  error
					}{
						{line: []byte("OK"), err: nil},
						{line: []byte{}, err: &pinentry.AssuanError{Code: pinentry.AssuanErrorCodeCancelled}},
						{line: []byte("BYE"), err: nil},
					},
				}
				return pinentry.NewClient(pinentry.WithProcess(&process))
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", nil
			},
		},
		{
			name:           "no pinentry binary",
			expectedResult: "",
			expectedErr:    fmt.Errorf("liner: function not supported in this terminal"),
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				return nil, fmt.Errorf("exec: \"pinentry\": executable file not found in $PATH")
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", errors.New("liner: function not supported in this terminal")
			},
		},
		{
			name:           "liner: no password provided",
			expectedResult: "",
			expectedErr:    fmt.Errorf("No password provided"),
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				return nil, fmt.Errorf("exec: \"pinentry\": executable file not found in $PATH")
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", nil
			},
		},
		{
			name:           "success",
			expectedResult: "password",
			expectedErr:    nil,
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				process := MockProcess{
					value:  "password",
					status: true,
					lines: []struct {
						line []byte
						err  error
					}{
						{line: []byte("OK"), err: nil},
						{line: []byte("D password"), err: nil},
						{line: []byte("OK"), err: nil},
						{line: []byte("BYE"), err: nil},
					},
				}
				return pinentry.NewClient(pinentry.WithProcess(&process))
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ope := getPinentry
			orp := readPassword
			defer func() {
				getPinentry = ope
				readPassword = orp
			}()
			getPinentry = test.mockClient
			readPassword = test.mockReadPassword
			actualResult, actualErr := getPassword()

			if string(actualResult) != test.expectedResult {
				t.Errorf("Expected password %q, but got %q", test.expectedResult, actualResult)
			}

			if test.expectedErr != nil {
				if actualErr.Error() != test.expectedErr.Error() {
					t.Errorf("Expected error %v, but got %v", test.expectedErr, actualErr)
				}
			}
		})
	}
}
