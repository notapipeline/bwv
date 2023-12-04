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

	"github.com/caarlos0/env/v10"
	"gopkg.in/yaml.v2"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/types"
)

// These functions are referenced as variables to enable them to
// be mocked in tests
var (
	ConfigPath func(m ConfigMode) string = getConfigPath
	getSecrets func() map[string]string  = tools.GetSecretsFromUserEnvOrStore
)

type Config struct {
	Server types.ServeCmd `yaml:"server"`

	Address string `yaml:"address" env:"BW_ADDRESS"`
	Port    int    `yaml:"port" env:"BW_PORT"`
	Token   string `yaml:"token" env:"BW_TOKEN"`
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
// The config file will be loaded from ~/.config/bwv/server.yaml if it exists
// and then the environment will be checked for overrides.
//
// Users are expected to call one of `MergeServerConfig` or `MergeClientConfig`
// to override the config with command line options.
func (c *Config) Load(m ConfigMode) (err error) {
	if err = c.loadYaml(m); err != nil {
		return
	}
	if err = c.loadEnv(); err != nil {
		return
	}

	return
}

func (c *Config) loadYaml(m ConfigMode) (err error) {
	var (
		cp       string = ConfigPath(m)
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

func (c *Config) loadEnv() (err error) {
	return env.Parse(c)
}

func (c *Config) MergeClientConfig(cmd types.ClientCmd) {
	if cmd.Server != "" {
		c.Address = cmd.Server
	}
	if cmd.Port != 0 {
		c.Port = cmd.Port
	}
	if cmd.Token != "" {
		c.Token = cmd.Token
	}
}

func (c *Config) MergeServerConfig(cmd types.ServeCmd) {
	if len(cmd.Whitelist) > 0 {
		c.Server.Whitelist = cmd.Whitelist
	}
	if len(cmd.ApiKeys) > 0 {
		for k, v := range cmd.ApiKeys {
			c.Server.ApiKeys[k] = v
		}
	}
	if cmd.Cert != "" {
		c.Server.Cert = cmd.Cert
	}
	if cmd.Key != "" {
		c.Server.Key = cmd.Key
	}
	if cmd.Port != 0 {
		c.Server.Port = cmd.Port
	}
	if cmd.Org != "" {
		c.Server.Org = cmd.Org
	}
	if cmd.Collection != "" {
		c.Server.Collection = cmd.Collection
	}
	if cmd.Debug {
		c.Server.Debug = cmd.Debug
	}
	if cmd.Quiet {
		c.Server.Quiet = cmd.Quiet
	}
	if cmd.SkipVerify {
		c.Server.SkipVerify = cmd.SkipVerify
	}
}

func (c *Config) IsSecure() (secure bool) {
	if c.Server.Cert != "" && c.Server.Key != "" {
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

	if c.Server.ApiKeys == nil {
		c.Server.ApiKeys = make(map[string]string)
	}
	c.Server.ApiKeys[hostOrCidr] = key

	var err error = c.Save()
	return token, err
}

func (c *Config) Save() (err error) {
	// Localhost address must always be whitelisted
	if len(c.Server.Whitelist) == 0 {
		c.Server.Whitelist = append(c.Server.Whitelist, "127.0.0.0/24")
	}

	var data []byte
	if data, err = yaml.Marshal(c); err != nil {
		return err
	}

	var cp string = ConfigPath(ConfigModeServer)
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

	for host, key := range c.Server.ApiKeys {
		if host == what || key == derivedWhat {
			revokedHost = host
			continue
		}
		keys[host] = key
	}
	c.Server.ApiKeys = keys
	err = c.Save()
	return revokedHost, err
}

func (c *Config) CheckApiKey(addr, key string) bool {
	if addr == "127.0.0.1" || tools.ContainsIp("127.0.0.1/24", addr) {
		secrets := getSecrets()
		if key == secrets["BW_CLIENTSECRET"] || key == secrets["BW_PASSWORD"] {
			return true
		}
	}

	// encrypt the token for comparison
	key = DeriveHttpGetAPIKey(key)
	for ip, k := range c.Server.ApiKeys {
		if k == key && (ip == addr || tools.ContainsIp(ip, addr)) {
			return true
		}
	}
	return false
}
