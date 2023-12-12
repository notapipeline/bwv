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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/caarlos0/env/v10"
	"gopkg.in/yaml.v2"

	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/types"
)

// These functions are referenced as variables to enable them to
// be mocked in tests
var (
	ConfigPath func(m ConfigMode) string      = getConfigPath
	GetSecrets func(v bool) map[string]string = tools.GetSecretsFromUserEnvOrStore
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
	c := Config{}
	return &c
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
		return
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

func (c *Config) MergeServerConfig(cmd *types.ServeCmd) {
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
	if cmd.Autoload {
		c.Server.Autoload = cmd.Autoload
	}
}

func (c *Config) IsSecure() (secure bool) {
	if c.Server.Cert != "" && c.Server.Key != "" {
		secure = true
	}
	return
}

func (c *Config) SetApiKey(address string, token types.CipherString) error {
	if c.Server.ApiKeys == nil {
		c.Server.ApiKeys = make(map[string]string)
	}
	if _, ok := c.Server.ApiKeys[address]; ok {
		return fmt.Errorf("token already exists for address %s", address)
	}
	c.Server.ApiKeys[address] = token.String()
	return c.Save()
}

func (c *Config) DeleteApiKey(address string) error {
	if _, ok := c.Server.ApiKeys[address]; !ok {
		return fmt.Errorf("no token exists for address %s", address)
	}
	delete(c.Server.ApiKeys, address)
	return c.Save()
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

func (c *Config) CheckApiKey(addr, key string) bool {
	secrets := GetSecrets(false)
	if addr == "127.0.0.1" || tools.ContainsIp("127.0.0.1/24", addr) {
		if key == secrets["BW_CLIENTSECRET"] || key == secrets["BW_PASSWORD"] {
			return true
		}
		return false
	}

	if key == secrets["BW_CLIENTSECRET"] || key == secrets["BW_PASSWORD"] {
		// If either of these come from anywhere other than localhost, we want
		// to kill the server and prevent unlock from taking place as this may
		// indicate a compromise of either the client secret or the master
		// password (or both)
		//
		// If this is reached, the user should change their master password and
		// client secret immediately.
		log.Println("-----------------------------------------------------------------------------------------------")
		log.Println("[FATAL] Possible compromise detected")
		log.Printf("        One of BW_CLIENTSECRET or BW_PASSWORD was used to authenticate from %s\n", addr)
		log.Println("        To protect the integrity of your vault, the server will now shut down and will not be restarted")
		log.Println("        Please change your master password and client secret immediately")
		log.Println("-----------------------------------------------------------------------------------------------")
		_ = os.WriteFile("/tmp/bwv-compromised", []byte("1"), 0600)
		log.Println("If this was a mistake or you have changed your master password and client secret, you can delete /tmp/bwv-compromised and restart the server")
		log.Fatal("dead")
		return false
	}

	for ip, k := range c.Server.ApiKeys {
		if k == key && (ip == addr || tools.ContainsIp(ip, addr)) {
			return true
		}
	}
	return false
}
