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
	Whitelist  []string          `yaml:"whitelist" env:"BW_WHITELIST" envSeparator:","`
	Cert       string            `yaml:"cert" env:"BW_CERT"`
	Key        string            `yaml:"key" env:"BW_KEY"`
	Port       int               `yaml:"port" env:"BW_PORT"`
	ApiKeys    map[string]string `yaml:"apikeys" env:"BW_APIKEYS" envSeparator:","`
	Org        string            `yaml:"org" env:"BW_ORG"`
	Collection string            `yaml:"collection" env:"BW_COLLECTION"`
	SkipVerify bool              `yaml:"skipverify" env:"BW_SKIPVERIFY"`
	Debug      bool              `yaml:"debug" env:"BW_DEBUG"`
	Quiet      bool              `yaml:"quiet" env:"BW_QUIET"`
}

type ClientCmd struct {
	Server     string `yaml:"server" env:"BW_SERVER"`
	Port       int    `yaml:"port" env:"BW_PORT"`
	SkipVerify bool   `yaml:"skipverify" env:"BW_SKIPVERIFY"`
	Token      string `yaml:"token" env:"BW_TOKEN"`
}
