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
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/types"
	"gopkg.in/yaml.v2"
)

// These functions are referenced as variables to enable them to
// be mocked in tests
var (
	configPath func(m ConfigMode) string = getConfigPath
	getSecrets func() map[string]string  = GetSecretsFromUserEnvOrStore
)

type Config struct {
	Whitelist []string          `yaml:"whitelist"`
	Cert      string            `yaml:"cert"`
	Key       string            `yaml:"key"`
	Port      int               `yaml:"port"`
	ApiKeys   map[string]string `yaml:"apikeys"`
	Token     string            `yaml:"token"`
}

type ConfigMode int

const (
	ConfigModeDefault ConfigMode = iota
	ConfigModeClient
	ConfigModeServer
)

func New() *Config {
	return &Config{}
}

// Load the config file from user local config directory
//
// The config file will be loaded from ~/.config/bwv/server.yaml
func (c *Config) Load(m ConfigMode) (err error) {
	var (
		cp       string = configPath(ConfigModeServer)
		yamlFile []byte
	)

	if _, err = os.Stat(cp); errors.Is(err, os.ErrNotExist) {
		return
	}
	if yamlFile, err = os.ReadFile(cp); err != nil {
		return err
	}

	log.Printf("Loading config file %s\n", cp)
	return yaml.Unmarshal(yamlFile, c)
}

func (c *Config) IsSecure() (secure bool) {
	if c.Cert != "" && c.Key != "" {
		secure = true
	}
	return
}

func DeriveHttpGetAPIKey(partial string) string {
	var (
		c   []byte
		err error
		kdf types.KDFInfo = types.KDFInfo{
			Type:       types.KDFTypePBKDF2,
			Iterations: 1,
		}
	)
	if c, err = crypto.DeriveMasterKey(cache.MasterPassword(), partial, kdf); err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(c)
}

func CreateToken() string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]rune, 32)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func (c *Config) AddApiKey(hostOrCidr string) (string, error) {
	var (
		token string = CreateToken()
		key          = DeriveHttpGetAPIKey(token)
	)
	c.ApiKeys[hostOrCidr] = key

	var err error = c.Save()
	return token, err
}

func (c *Config) Save() (err error) {
	if len(c.Whitelist) == 0 {
		c.Whitelist = append(c.Whitelist, "127.0.0.0/24")
	}
	var data []byte
	if data, err = yaml.Marshal(c); err != nil {
		return err
	}

	var cp string = configPath(ConfigModeServer)
	if err = os.MkdirAll(filepath.Dir(cp), 0700); err != nil {
		return err
	}
	return os.WriteFile(cp, data, 0600)
}

func getConfigPath(m ConfigMode) string {
	home, _ := os.UserHomeDir()
	if m == ConfigModeClient {
		return fmt.Sprintf("%s/.config/bwv/client.yaml", home)
	}
	return fmt.Sprintf("%s/.config/bwv/server-test.yaml", home)
}

func (c *Config) RevokeApiKey(what string) (string, error) {
	var (
		keys        map[string]string = make(map[string]string)
		revokedHost string            = ""
		derivedWhat string            = DeriveHttpGetAPIKey(what)
		err         error
	)

	for host, key := range c.ApiKeys {
		if host == what || key == derivedWhat {
			revokedHost = host
			continue
		}
		keys[host] = key
	}
	c.ApiKeys = keys
	err = c.Save()
	return revokedHost, err
}

func (c *Config) CheckApiKey(addr, key string) bool {
	if addr == "127.0.0.1" || ContainsIp("127.0.0.1/24", addr) {
		secrets := getSecrets()
		if key == secrets["BW_CLIENTSECRET"] || key == secrets["BW_PASSWORD"] {
			return true
		}
	}

	// encrypt the token for comparison
	key = DeriveHttpGetAPIKey(key)
	for ip, k := range c.ApiKeys {
		if k == key && (ip == addr || ContainsIp(ip, addr)) {
			return true
		}
	}
	return false
}
