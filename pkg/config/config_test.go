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
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/types"
)

var pbkdf types.KDFInfo = types.KDFInfo{
	Type:        types.KDFTypePBKDF2,
	Iterations:  800000,
	Memory:      types.IntPtr(0),
	Parallelism: types.IntPtr(0),
}

func setupSuite(t *testing.T) func(t *testing.T) {
	t.Log("Setting up config suite")
	tempDir := t.TempDir()
	ConfigPath = func(m ConfigMode) string {
		return filepath.Join(tempDir, "server.yaml")
	}
	err := os.WriteFile(ConfigPath(ConfigModeServer), []byte(`
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
		ConfigPath = getConfigPath
		GetSecrets = tools.GetSecretsFromUserEnvOrStore
		cache.Reset()
	}
}

func TestConfig_Load(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	// Create a temporary config file
	// Load the config
	c := New()
	if err := c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Verify the loaded values
	expectedWhitelist := []string{"127.0.0.0/24"}
	if len(c.Server.Whitelist) != len(expectedWhitelist) {
		t.Errorf("Expected whitelist length %d but got %d", len(expectedWhitelist), len(c.Server.Whitelist))
	}

	for i, ip := range c.Server.Whitelist {
		if ip != expectedWhitelist[i] {
			t.Errorf("Expected whitelist IP %q but got %q", expectedWhitelist[i], ip)
		}
	}

	expectedCert := "cert.pem"
	if c.Server.Cert != expectedCert {
		t.Errorf("Expected cert %q but got %q", expectedCert, c.Server.Cert)
	}

	expectedKey := "key.pem"
	if c.Server.Key != expectedKey {
		t.Errorf("Expected key %q but got %q", expectedKey, c.Server.Key)
	}

	expectedPort := 8080
	if c.Server.Port != expectedPort {
		t.Errorf("Expected port %d but got %d", expectedPort, c.Server.Port)
	}

	expectedAPIKeys := map[string]string{"example.com": "abcdef123456"}
	if len(c.Server.ApiKeys) != len(expectedAPIKeys) {
		t.Errorf("Expected API keys length %d but got %d", len(expectedAPIKeys), len(c.Server.ApiKeys))
	}

	for host, key := range c.Server.ApiKeys {
		if expectedAPIKeys[host] != key {
			t.Errorf("Expected API key %q for host %q but got %q", expectedAPIKeys[host], host, key)
		}
	}
}

func TestConfig_IsSecure(t *testing.T) {
	c := New()
	if c.IsSecure() {
		t.Error("Expected IsSecure to return false when cert and key are empty")
	}

	c.Server.Cert = "cert.pem"
	if c.IsSecure() {
		t.Error("Expected IsSecure to return false when key is empty")
	}

	c.Server.Key = "key.pem"
	if !c.IsSecure() {
		t.Error("Expected IsSecure to return true when cert and key are not empty")
	}
}

func TestConfig_Save(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance([]byte("masterpw"), []byte("email@example.com"), pbkdf); err != nil {
		t.Fatal(err)
	}

	// Create a new config
	c := New()
	var (
		err  error
		data []byte
	)

	if err = c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	c.Server.Cert = "cert.pem"
	c.Server.Key = "key.pem"
	c.Server.Port = 8080
	c.Server.ApiKeys = map[string]string{"example.com": "abcdef123456"}

	// Save the config
	if err = c.Save(); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Verify the saved config file
	if data, err = os.ReadFile(ConfigPath(ConfigModeServer)); err != nil {
		t.Fatal(err)
	}

	expectedData := []byte(`server:
  whitelist:
  - 127.0.0.0/24
  cert: cert.pem
  key: key.pem
  server: ""
  port: 8080
  apikeys:
    example.com: abcdef123456
  org: ""
  collection: ""
  skipverify: false
  debug: false
  quiet: false
  autoload: false
address: ""
port: 0
token: ""
`)
	if string(data) != string(expectedData) {
		t.Errorf("Expected saved config file:\n%s===\n\nBut got:\n%s===", string(expectedData), string(data))
	}
}

func TestConfig_CheckApiKey_Localhost(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance([]byte("masterpw"), []byte("email@example.com"), pbkdf); err != nil {
		t.Fatal(err)
	}
	// Create a new config
	c := New()
	if err := c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Check the API key for localhost
	addr := "127.0.0.1"
	key := []byte("abcdef123456")
	GetSecrets = func(v bool) map[string][]byte {
		return map[string][]byte{
			"BW_CLIENTSECRET": key,
		}
	}

	if !c.CheckApiKey(addr, key) {
		t.Errorf("Expected API key %q for address %q to be valid", key, addr)
	}
}

func TestConfig_CheckApiKey_EnvironmentVariables(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance([]byte("masterpw"), []byte("email@example.com"), pbkdf); err != nil {
		t.Fatal(err)
	}
	// Create a new config
	c := New()
	if err := c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Set the environment variables
	os.Setenv("BW_CLIENTSECRET", "abcdef123456")
	os.Setenv("BW_PASSWORD", "abcdef123456")

	// Check the API key for localhost
	addr := "127.0.0.1"
	key := []byte("abcdef123456")

	if !c.CheckApiKey(addr, key) {
		t.Errorf("Expected API key %q for address %q to be valid", key, addr)
	}

	// Clean up the environment variables
	os.Unsetenv("BW_CLIENTSECRET")
	os.Unsetenv("BW_PASSWORD")
}

func TestConfig_CheckApiKey_InvalidKey(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance([]byte("masterpw"), []byte("email@example.com"), pbkdf); err != nil {
		t.Fatal(err)
	}
	// Create a new config
	c := New()
	if err := c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Check an invalid API key
	addr := "127.0.0.1"
	key := []byte("invalidkey")

	if c.CheckApiKey(addr, key) {
		t.Errorf("Expected API key %q for address %q to be invalid", key, addr)
	}
}
