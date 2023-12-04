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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/spf13/cobra"
)

func setupSuite(t *testing.T) func(t *testing.T) {
	t.Log("Setting up config suite")
	tempDir := t.TempDir()
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
		config.ConfigPath = ocp
		cache.Reset()
	}
}

func TestRootCmdThrowsErrorOnMissingClientConfig(t *testing.T) {
	// Create a new test command
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	config.ConfigPath = func(m config.ConfigMode) string {
		return "/this/path/to/bwv/client/config/will/never/exist/client.yaml"
	}
	// Add the test command as a subcommand of the root command
	rootCmd.AddCommand(testCmd)

	// Create a new buffer to capture the command's output
	buf := new(bytes.Buffer)

	// Set the command's output to the buffer
	rootCmd.SetOutput(buf)

	// Execute the root command
	var err error
	if err = rootCmd.Execute(); err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Verify that the output contains the expected string
	expectedOutput := "Error: stat /this/path/to/bwv/client/config/will/" +
		"never/exist/client.yaml: no such file or director"
	actualOutput := buf.String()
	if !strings.Contains(actualOutput, expectedOutput) {
		t.Fatalf("Expected output to contain %q but got %q", expectedOutput, buf.String())
	}

	// Verify that the test command is a subcommand of the root command
	found := false
	for _, c := range rootCmd.Commands() {
		if c == testCmd {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected test command to be a subcommand of root command")
	}
}

func TestRootCmd(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	// Create a new test command
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	// Add the test command as a subcommand of the root command
	rootCmd.AddCommand(testCmd)

	// Create a new buffer to capture the command's output
	buf := new(bytes.Buffer)

	// Set the command's output to the buffer
	rootCmd.SetOutput(buf)

	// Execute the root command
	Execute()

	// Verify that the output contains the expected string
	expectedOutput := "Usage"
	actualOutput := buf.String()
	if !strings.Contains(actualOutput, expectedOutput) {
		t.Fatalf("Expected output to contain %q but got %q", expectedOutput, buf.String())
	}

	// Verify that the test command is a subcommand of the root command
	found := false
	for _, c := range rootCmd.Commands() {
		if c == testCmd {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected test command to be a subcommand of root command")
	}
}

func TestRootCmdRewriteArguments(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	// Create a new test command
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	// Add the test command as a subcommand of the root command
	rootCmd.AddCommand(testCmd)

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
	t.Log(os.Args)
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

	// Verify that the test command is a subcommand of the root command
	found := false
	for _, c := range rootCmd.Commands() {
		if c == testCmd {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected test command to be a subcommand of root command")
	}
}
