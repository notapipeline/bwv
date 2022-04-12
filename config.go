/*
 *   Copyright 2022 Martin Proffitt <mproffitt@choclab.net>
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
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/notapipeline/bwv/pkg/bitw"
	"gopkg.in/yaml.v2"
)

func (s *server) AddApiKey(hostOrCidr string) {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]rune, 32)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	var key = bitw.DeriveHttpGetAPIKey(string(b))
	s.ApiKeys[hostOrCidr] = key

	s.save()
	fmt.Printf("\n========================================\ntoken = %s\n========================================\n\n", string(b))
}

func (s *server) save() {
	if len(s.Whitelist) == 0 {
		s.Whitelist = append(s.Whitelist, "127.0.0.0/24")
	}
	data, err := yaml.Marshal(&s)
	if err != nil {
		log.Fatal(err)
	}

	var configPath string = getConfigPath()
	os.MkdirAll(filepath.Dir(configPath), os.ModePerm)
	err = ioutil.WriteFile(configPath, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *server) RevokeApiKey(key string) string {
	var keys map[string]string = make(map[string]string)
	var retVal string = ""
	for k, v := range s.ApiKeys {
		if k == key || v == bitw.DeriveHttpGetAPIKey(key) {
			retVal = k
			continue
		}
		keys[k] = v
	}
	s.ApiKeys = keys
	s.save()
	return retVal
}

func (s *server) checkApiKey(addr, key string) bool {
	if addr == "127.0.0.1" || containsIp("127.0.0.1/24", addr) {
		secrets := getSecretsFromEnvOrStore()
		if key == secrets["BW_CLIENTSECRET"] || key == secrets["BW_PASSWORD"] {
			return true
		}
	}
	key = bitw.DeriveHttpGetAPIKey(key)
	for ip, k := range s.ApiKeys {
		if k == key && (ip == addr || containsIp(ip, addr)) {
			return true
		}
	}
	return false
}
