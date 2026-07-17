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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

func TestGenkeyCmd(t *testing.T) {
	tests := []struct {
		name        string
		addresses   []string
		expectedErr error
		responses   []transport.MockHttpResponse
	}{
		{
			name:        "success",
			addresses:   []string{"192.168.0.1"},
			expectedErr: nil,
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 200,
					Body: []byte(`{"message":{"192.168.0.1":"11111111111111111111111111111111"}}`),
				},
			},
		},
		{
			name:        "cidr block",
			addresses:   []string{"10.0.0.0/8"},
			expectedErr: nil,
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 200,
					Body: []byte(`{"message":{"10.0.0.0/8":"11111111111111111111111111111111"}}`),
				},
			},
		},
		{
			name:        "rejects non-network cidr",
			addresses:   []string{"192.168.0.5/16"},
			expectedErr: fmt.Errorf(`CIDR block "192.168.0.5/16" is not a network address (did you mean "192.168.0.0/16"?)`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport.DefaultHttpClient = &transport.MockHttpClient{
				Responses: test.responses,
			}

			var (
				r        *os.File
				w        *os.File
				err      error
				response map[string]string
				buf      bytes.Buffer
			)
			defer func() { _ = w.Close() }()

			log.SetOutput(&buf)

			of := fatal
			orig := os.Stdout
			defer func() {
				fatal = of
				log.SetFlags(log.Flags() & (log.Ldate | log.Ltime))

				os.Stdout = orig
			}()
			fatal = func(format string, v ...any) {
				log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
				log.Printf(format, v...)
			}

			if r, w, err = os.Pipe(); err != nil {
				t.Errorf("Unable to create pipe: %q", err)
				return
			}
			os.Stdout = w

			addresses = nil // pflag StringSlice appends across in-process Execute calls
			os.Args = []string{"bwv", "key", "gen"}
			for _, address := range test.addresses {
				os.Args = append(os.Args, "-a", address)
			}
			Execute()
			_ = w.Close()

			var stdoutbuf strings.Builder
			_, err = io.Copy(&stdoutbuf, r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "testing: copying pipe: %v\n", err)
				os.Exit(1)
			}

			o := stdoutbuf.String()

			if test.expectedErr != nil {
				var (
					expected = strings.TrimSpace(test.expectedErr.Error())
					actual   = strings.TrimSpace(buf.String())
				)
				if expected != actual {
					t.Errorf("Expected log output %q, but got %q", expected, actual)
				}
				return
			}

			// gen must POST the store-token endpoint with exactly the requested
			// addresses (IPs and CIDR blocks alike) - no empty-string padding.
			mock := transport.DefaultHttpClient.(*transport.MockHttpClient)
			if !strings.HasSuffix(mock.LastPostURL, "/api/v1/storetoken") {
				t.Errorf("gen posted to %q, want suffix /api/v1/storetoken", mock.LastPostURL)
			}
			if got, ok := mock.LastPostBody.([]string); !ok || !reflect.DeepEqual(got, test.addresses) {
				t.Errorf("gen sent addresses %#v, want %#v", mock.LastPostBody, test.addresses)
			}

			if err = json.Unmarshal([]byte(o), &response); err != nil {
				t.Errorf("Unable to unmarshal response body: %q", err)
			}
			for _, address := range test.addresses {
				if _, ok := response[address]; !ok {
					t.Errorf("Expected response to contain %q, but got %q", address, response)
				}
			}
		})
	}
}

func TestRevokeCmd(t *testing.T) {
	tests := []struct {
		name            string
		addresses       []string
		kdf             types.KDFInfo
		expectedErr     error
		expectedSuccess string
		expectedFailed  string
		responses       []transport.MockHttpResponse
	}{
		{
			name: "full revoke test success and failed",
			addresses: []string{
				"127.0.0.1",
				"192.168.0.1",
			},
			expectedErr:     nil,
			expectedSuccess: "Token revoked for address 127.0.0.1",
			expectedFailed:  "Token not revoked for address 192.168.0.1",
			responses: []transport.MockHttpResponse{
				{
					Code: 200,
					Body: []byte(`{"kdf":0,"kdfIterations":1000,"kdfMemory":null,"kdfParallelism":null}`),
				},
				{
					Code: 200,
					Body: []byte(`{"message":{"revoked": ["127.0.0.1"],"failed": ["192.168.0.1"]}}`),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			fatal = func(format string, v ...any) {
				log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
				log.Printf(format, v...)
			}

			addresses = nil // pflag StringSlice appends across in-process Execute calls
			os.Args = []string{"bwv", "key", "revoke"}
			for _, address := range test.addresses {
				os.Args = append(os.Args, "-a", address)
			}

			Execute()

			// revoke must hit the revoke endpoint, not store-token.
			mock := transport.DefaultHttpClient.(*transport.MockHttpClient)
			if !strings.HasSuffix(mock.LastPostURL, "/api/v1/revoketoken") {
				t.Errorf("revoke posted to %q, want suffix /api/v1/revoketoken", mock.LastPostURL)
			}
			var actual = strings.TrimSpace(buf.String())
			if test.expectedErr != nil {
				var expected = strings.TrimSpace(test.expectedErr.Error())

				if expected != actual {
					t.Errorf("Expected log output %q, but got %q", expected, actual)
				}
				return
			}
			t.Log(buf.String())
			if !strings.Contains(buf.String(), test.expectedSuccess) {
				t.Errorf("Expected log output to contain %q, but got %q", test.expectedSuccess, buf.String())
			}

			if !strings.Contains(buf.String(), test.expectedFailed) {
				t.Errorf("Expected log output to contain %q, but got %q", test.expectedFailed, buf.String())
			}
		})
	}
}

func TestValidateAddresses(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []string
		wantErr bool
	}{
		{"single ip", []string{"192.168.0.1"}, false},
		{"ipv6", []string{"::1"}, false},
		{"cidr network", []string{"10.0.0.0/8"}, false},
		{"mixed ip and cidr", []string{"192.168.0.1", "10.0.0.0/8"}, false},
		{"empty", nil, true},
		{"garbage", []string{"not-an-address"}, true},
		{"non-network cidr", []string{"192.168.0.5/16"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateAddresses(tt.addrs); (err != nil) != tt.wantErr {
				t.Errorf("validateAddresses(%v) error = %v, wantErr %v", tt.addrs, err, tt.wantErr)
			}
		})
	}
}
