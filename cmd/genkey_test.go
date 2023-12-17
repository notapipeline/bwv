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
	"net"
	"os"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/transport"
)

func TestGenkeyCmd(t *testing.T) {
	tests := []struct {
		name        string
		addresses   []net.IP
		expectedErr error
		responses   []transport.MockHttpResponse
	}{
		{
			name: "success",
			addresses: []net.IP{
				net.ParseIP("192.168.0.1"),
			},
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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

			orig := os.Stdout
			defer func() {
				os.Stdout = orig
			}()

			var (
				r        *os.File
				w        *os.File
				err      error
				response map[string]string
			)
			defer w.Close()

			if r, w, err = os.Pipe(); err != nil {
				t.Errorf("Unable to create pipe: %q", err)
				return
			}
			os.Stdout = w

			os.Args = []string{"bwv", "key", "genkey", "-a", "192.168.0.1"}
			genkeyCmd.Run(genkeyCmd, os.Args)
			w.Close()

			var stdoutbuf strings.Builder
			_, err = io.Copy(&stdoutbuf, r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "testing: copying pipe: %v\n", err)
				os.Exit(1)
			}

			o := stdoutbuf.String()

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

			if err = json.Unmarshal([]byte(o), &response); err != nil {
				t.Errorf("Unable to unmarshal response body: %q", err)
			}
			for _, address := range test.addresses {
				if _, ok := response[address.String()]; !ok {
					t.Errorf("Expected response to contain %q, but got %q", address.String(), response)
				}
			}
		})
	}
}
