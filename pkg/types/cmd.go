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
package types

type ServeCmd struct {
	Cert       string            `yaml:"cert" env:"BW_CERT"`
	Key        string            `yaml:"key" env:"BW_KEY"`
	Server     string            `yaml:"server" env:"BW_SERVER"`
	Port       int               `yaml:"port" env:"BW_PORT"`
	ApiKeys    map[string]string `yaml:"apikeys" env:"BW_APIKEYS" envSeparator:","`
	Org        string            `yaml:"org" env:"BW_ORG"`
	Collection string            `yaml:"collection" env:"BW_COLLECTION"`
	SkipVerify bool              `yaml:"skipverify" env:"BW_SKIPVERIFY"`
	Debug      bool              `yaml:"debug" env:"BW_DEBUG"`
	Quiet      bool              `yaml:"quiet" env:"BW_QUIET"`
	Autoload   bool              `yaml:"autoload" env:"BW_AUTOLOAD"`
}

func (s *ServeCmd) Merge(c *ClientCmd) {
	if s.Server == "" {
		s.Server = c.Server
	}
	if s.Port == 0 {
		s.Port = c.Port
	}
	if !s.SkipVerify {
		s.SkipVerify = c.SkipVerify
	}

	if !s.Debug {
		s.Debug = c.Debug
	}

	if !s.Quiet {
		s.Quiet = c.Quiet
	}
}

type ClientCmd struct {
	Server     string `yaml:"server" env:"BW_SERVER"`
	Port       int    `yaml:"port" env:"BW_PORT"`
	SkipVerify bool   `yaml:"skipverify" env:"BW_SKIPVERIFY"`
	Debug      bool   `yaml:"debug" env:"BW_DEBUG"`
	Quiet      bool   `yaml:"quiet" env:"BW_QUIET"`
	Token      string `yaml:"token" env:"BW_TOKEN"`
	Output     string `yaml:"output" env:"BW_OUTPUT"`
}

type VaultItem struct {
	Path        string
	Fields      []string
	Parameters  []string
	Attachments []string
	Notes       bool
	SecureNotes bool
}
