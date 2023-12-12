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
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

func setupSuite(t *testing.T) func(t *testing.T) {
	t.Log("Setting up config suite")
	tempDir := t.TempDir()
	vaultItem = types.VaultItem{}
	ocp := config.ConfigPath
	config.ConfigPath = func(m config.ConfigMode) string {
		return filepath.Join(tempDir, "client.yaml")
	}
	err := os.WriteFile(config.ConfigPath(config.ConfigModeServer), []byte(`
token: ocjJueD4tiXXdCNIDVhhiOyS9XOHxDXg
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	return func(t *testing.T) {
		getSecretsFromUserEnvOrStore = tools.GetSecretsFromUserEnvOrStore
		config.ConfigPath = ocp
		cache.Reset()
	}
}

func TestRootCmdRewriteArguments(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	transport.DefaultHttpClient = &transport.MockHttpClient{}

	// Create a new buffer to capture the command's output
	buf := new(bytes.Buffer)

	// Set the command's output to the buffer
	rootCmd.SetOutput(buf)

	// Execute the root command
	os.Args = []string{"bwv", "--config", "config", "--server", "localhost",
		"--port", "6278", "-t", "token", "hello/world", "-f", "field1,field2",
		"-p", "param1", "-p", "param2", "--skip-verify",
	}
	Execute()
	if !reflect.DeepEqual(os.Args, []string{"bwv", "--config", "config",
		"--server", "localhost", "--port", "6278", "-t", "token",
		"-P", "hello/world", "-f", "field1,field2", "-p", "param1",
		"-p", "param2", "--skip-verify",
	}) {
		t.Fatalf("Expected arguments to be rewritten, got %q", os.Args)
	}

	// Verify that the output contains the expected string
	expectedOutput := ""
	actualOutput := buf.String()
	if !strings.Contains(actualOutput, expectedOutput) {
		t.Fatalf("Expected output to contain %q but got %q", expectedOutput, buf.String())
	}
}

func TestRootCmd(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedError  bool
		expectedOutput string
		mocks          func()
	}{
		{
			name:           "TestRootCmd",
			args:           []string{"bwv", "-t", "token"},
			expectedError:  false,
			expectedOutput: "",
			mocks: func() {
				transport.DefaultHttpClient = &transport.MockHttpClient{}
			},
		},
		{
			name:           "root command fails if no path specified",
			args:           []string{"bwv", "-t", "token", "-p", "something"},
			expectedError:  true,
			expectedOutput: "Error: no path specified",
			mocks: func() {
				transport.DefaultHttpClient = &transport.MockHttpClient{}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			teardownSuite := setupSuite(t)
			defer teardownSuite(t)

			test.mocks()

			// Create a new buffer to capture the command's output
			var logbuf bytes.Buffer
			log.SetOutput(&logbuf)

			of := fatal
			defer func() {
				fatal = of
				log.SetFlags(log.Flags() & (log.Ldate | log.Ltime))
			}()
			fatal = func(format string, v ...interface{}) {
				log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
				log.Printf(format, v...)
			}

			// Set the command's output to the buffer
			var buf *bytes.Buffer = new(bytes.Buffer)
			rootCmd.SetOutput(buf)

			os.Args = test.args
			// Execute the root command
			Execute()

			// Verify that the output contains the expected string
			if test.expectedError {
				actualOutput := logbuf.String()
				if !strings.Contains(actualOutput, test.expectedOutput) {
					t.Fatalf("Expected log output to contain %q but got %q", test.expectedOutput, logbuf.String())
				}
				return
			}

			actualOutput := buf.String()
			if !strings.Contains(actualOutput, test.expectedOutput) {
				t.Fatalf("Expected output to contain %q but got %q", test.expectedOutput, buf.String())
			}
		})
	}
}
