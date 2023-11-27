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
		getPassword func() (string, error)
		responses   []struct {
			code int
			body string
		}
	}{
		{
			name:        "test successful revoke",
			email:       "email@example.com",
			address:     "127.0.0.1",
			password:    "password",
			expectedErr: nil,
			getPassword: func() (string, error) {
				return "password", nil
			},
			responses: []struct {
				code int
				body string
			}{
				{
					code: 200,
					body: `{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`,
				},
				{
					code: 200,
					body: `{"statuscode": 200, "message":"Token revoked for address 127.0.0.1"}`,
				},
			},
		},
		{
			name:        "test invalid email",
			email:       "email",
			address:     "127.0.0.1",
			password:    "password",
			expectedErr: errors.New("invalid email address \"mail: missing '@' or angle-addr\""),
			getPassword: func() (string, error) {
				return "password", nil
			},
			responses: []struct {
				code int
				body string
			}{
				{
					code: 200,
					body: `{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`,
				},
				{
					code: 0,
					body: "",
				},
			},
		},
		{
			name:        "test invalid password",
			email:       "email@example.com",
			address:     "127.0.0.1",
			password:    "",
			expectedErr: errors.New("invalid password \"invalid password\""),
			getPassword: func() (string, error) {
				return "", errors.New("invalid password")
			},
			responses: []struct {
				code int
				body string
			}{
				{
					code: 200,
					body: `{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`,
				},
				{
					code: 0,
					body: "",
				},
			},
		},
		{
			name:    "rate limited",
			address: "localhost",
			email:   "test@example.com",
			getPassword: func() (string, error) {
				return "", nil
			},
			expectedErr: errors.New(`unable to get kdf info: "Bad Request: {\"message\":\"Traffic from your network looks unusual. Connect to a different network or try again later. [Error Code 6]\"}"`),
			responses: []struct {
				code int
				body string
			}{
				{
					code: 400,
					body: `{"message":"Traffic from your network looks unusual. Connect to a different network or try again later. [Error Code 6]"}`,
				},
				{
					code: 400,
					body: `{"message":"Traffic from your network looks unusual. Connect to a different network or try again later. [Error Code 6]"}`,
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
			transport.DefaultHttpClient = &MockHttpClient{
				responses: test.responses,
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
			if !strings.Contains(buf.String(), "Token revoked for address 127.0.0.1") {
				t.Errorf("Expected log output to contain %q, but got %q", "Token revoked for address 127.0.0.1", buf.String())
			}
		})
	}
}
