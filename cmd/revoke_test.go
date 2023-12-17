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
	"log"
	"os"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

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
			fatal = func(format string, v ...interface{}) {
				log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
				log.Printf(format, v...)
			}

			os.Args = []string{"bwv", "key", "revoke"}
			for _, address := range test.addresses {
				os.Args = append(os.Args, "-a", address)
			}

			Execute()
			var actual string = strings.TrimSpace(buf.String())
			if test.expectedErr != nil {
				var expected string = strings.TrimSpace(test.expectedErr.Error())

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
