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
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/notapipeline/bwv/pkg/cache"
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
	configPath = func(m ConfigMode) string {
		return filepath.Join(tempDir, "server.yaml")
	}
	err := os.WriteFile(configPath(ConfigModeServer), []byte(`
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
		configPath = getConfigPath
		getSecrets = GetSecretsFromUserEnvOrStore
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
	if len(c.Whitelist) != len(expectedWhitelist) {
		t.Errorf("Expected whitelist length %d but got %d", len(expectedWhitelist), len(c.Whitelist))
	}

	for i, ip := range c.Whitelist {
		if ip != expectedWhitelist[i] {
			t.Errorf("Expected whitelist IP %q but got %q", expectedWhitelist[i], ip)
		}
	}

	expectedCert := "cert.pem"
	if c.Cert != expectedCert {
		t.Errorf("Expected cert %q but got %q", expectedCert, c.Cert)
	}

	expectedKey := "key.pem"
	if c.Key != expectedKey {
		t.Errorf("Expected key %q but got %q", expectedKey, c.Key)
	}

	expectedPort := 8080
	if c.Port != expectedPort {
		t.Errorf("Expected port %d but got %d", expectedPort, c.Port)
	}

	expectedAPIKeys := map[string]string{"example.com": "abcdef123456"}
	if len(c.ApiKeys) != len(expectedAPIKeys) {
		t.Errorf("Expected API keys length %d but got %d", len(expectedAPIKeys), len(c.ApiKeys))
	}

	for host, key := range c.ApiKeys {
		if expectedAPIKeys[host] != key {
			t.Errorf("Expected API key %q for host %q but got %q", expectedAPIKeys[host], host, key)
		}
	}
}

func TestConfig_IsSecure(t *testing.T) {
	c := &Config{}
	if c.IsSecure() {
		t.Error("Expected IsSecure to return false when cert and key are empty")
	}

	c.Cert = "cert.pem"
	if c.IsSecure() {
		t.Error("Expected IsSecure to return false when key is empty")
	}

	c.Key = "key.pem"
	if !c.IsSecure() {
		t.Error("Expected IsSecure to return true when cert and key are not empty")
	}
}

func TestDeriveHttpGetAPIKey(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
		t.Fatal(err)
	}

	partial := "email@example.com"
	key := DeriveHttpGetAPIKey(partial)
	t.Log("Derived API key:", key)
	if _, err := base64.StdEncoding.DecodeString(key); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}
}

func TestConfig_AddApiKey(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
		t.Fatal(err)
	}

	var (
		c          *Config = New()
		hostOrCidr string  = "example.com"
		key        string
		ok         bool
		err        error
		token      string
	)

	if err = c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	if token, err = c.AddApiKey(hostOrCidr); err != nil {
		t.Fatal(err)
	}

	if key, ok = c.ApiKeys[hostOrCidr]; !ok {
		t.Errorf("Expected API key for host %q to be added", hostOrCidr)
	}

	if key != DeriveHttpGetAPIKey(token) {
		t.Errorf("Expected API key %q for host %q but got %q", DeriveHttpGetAPIKey(token), hostOrCidr, key)
	}

	t.Logf("API key for host %q: %q", hostOrCidr, key)
	if _, err := base64.StdEncoding.DecodeString(key); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}
}

func TestConfig_Save(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
		t.Fatal(err)
	}

	// Create a new config
	var (
		c    *Config = New()
		err  error
		data []byte
	)

	if err = c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	c.Cert = "cert.pem"
	c.Key = "key.pem"
	c.Port = 8080
	c.ApiKeys = map[string]string{"example.com": "abcdef123456"}

	// Save the config
	if err = c.Save(); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Verify the saved config file
	if data, err = os.ReadFile(configPath(ConfigModeServer)); err != nil {
		t.Fatal(err)
	}

	expectedData := []byte(`whitelist:
- 127.0.0.0/24
cert: cert.pem
key: key.pem
port: 8080
apikeys:
  example.com: abcdef123456
`)
	if string(data) != string(expectedData) {
		t.Errorf("Expected saved config file:\n%s===\n\nBut got:\n%s===", string(expectedData), string(data))
	}
}

func TestConfig_RevokeApiKey(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
		t.Fatal(err)
	}
	// Create a new config
	c := New()
	if err := c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Add an API key
	var (
		hostOrCidr  string = "example.com"
		token       string
		err         error
		revokedHost string
	)
	if token, err = c.AddApiKey(hostOrCidr); err != nil {
		t.Fatal(err)
	}

	// Revoke the API key
	if revokedHost, err = c.RevokeApiKey(token); err != nil {
		t.Fatal(err)
	}

	// Verify the revoked API key
	if revokedHost != hostOrCidr {
		t.Errorf("Expected revoked host %q but got %q", hostOrCidr, revokedHost)
	}
	if _, ok := c.ApiKeys[hostOrCidr]; ok {
		t.Errorf("Expected API key for host %q to be revoked", hostOrCidr)
	}
}

func TestConfig_CheckApiKey(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
		t.Fatal(err)
	}

	var (
		c     *Config = New()
		err   error
		token string
	)

	if err = c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	hosts := map[string]string{
		"example.com":  "",
		"192.168.0.1":  "",
		"127.0.0.1/24": "",
	}
	for host := range hosts {
		if token, err = c.AddApiKey(host); err != nil {
			t.Fatal(err)
		}
		hosts[host] = token
	}

	for host, key := range hosts {
		if !c.CheckApiKey(host, key) {
			t.Errorf("Expected API key %q for host %q to be valid", key, host)
		}
	}
}

func TestConfig_CheckApiKey_Localhost(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
		t.Fatal(err)
	}
	// Create a new config
	c := New()
	if err := c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Check the API key for localhost
	addr := "127.0.0.1"
	key := "abcdef123456"
	getSecrets = func() map[string]string {
		return map[string]string{
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
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
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
	key := "abcdef123456"

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
	if _, err := cache.Instance("masterpw", "email@example.com", pbkdf); err != nil {
		t.Fatal(err)
	}
	// Create a new config
	c := New()
	if err := c.Load(ConfigModeServer); err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	// Check an invalid API key
	addr := "127.0.0.1"
	key := "invalidkey"

	if c.CheckApiKey(addr, key) {
		t.Errorf("Expected API key %q for address %q to be invalid", key, addr)
	}
}
func TestGetConfigPath(t *testing.T) {
	expectedPath := filepath.Join(os.Getenv("HOME"), ".config/bwv/server.yaml")
	actualPath := getConfigPath(ConfigModeServer)
	if actualPath != expectedPath {
		t.Errorf("Expected config path %q but got %q", expectedPath, actualPath)
	}
}
