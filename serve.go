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
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/hokaccha/go-prettyjson"
	"github.com/notapipeline/bwv/pkg/bitw"
	"gopkg.in/yaml.v2"
)

const DefaultPort = 6277

type server struct {
	Whitelist []string          `yaml:"whitelist"`
	Cert      string            `yaml:"cert"`
	Key       string            `yaml:"key"`
	Port      int               `yaml:"port"`
	ApiKeys   map[string]string `yaml:"apikeys"`
}

func (s *server) IsSecure() (secure bool) {
	secure = false
	if s.Cert != "" && s.Key != "" {
		secure = true
	}
	return
}

func getConfigPath() string {
	home, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.config/bwv/server.yaml", home)
}

func unique(what []string) (unique []string) {
	unique = make([]string, 0, len(what))
	m := map[string]bool{}

	for _, v := range what {
		if !m[v] {
			m[v] = true
			unique = append(unique, v)
		}
	}
	return
}

func (s *server) parseFields(c bitw.DecryptedCipher, fieldString string) (keys []string, values map[string]interface{}) {
	var (
		ok     bool = false
		fields      = unique(strings.Split(fieldString, ","))
	)
	keys = make([]string, 0)
	values = make(map[string]interface{})

	for _, f := range fields {
		var v interface{}
		if v, ok = c.Fields[f]; ok && v != "" {
			keys = append(keys, f)
			values[f] = v
		}
	}
	return
}

func (s *server) parseProperties(c bitw.DecryptedCipher, propertyString string) (keys []string, values map[string]interface{}) {
	var properties = unique(strings.Split(propertyString, ","))
	keys = make([]string, 0)
	values = make(map[string]interface{})

	for _, p := range properties {
		var v interface{}
		if v = c.Get(p); v != "" && v != nil {
			keys = append(keys, p)
			values[p] = v
		}
	}
	return
}

func (s *server) getHttpPath(w http.ResponseWriter, r *http.Request) {
	var (
		addr         string   = strings.Split(r.RemoteAddr, ":")[0]
		useWhitelist bool     = len(s.Whitelist) != 0
		matched      bool     = !useWhitelist
		auth         []string = strings.Split(r.Header.Get("Authorization"), " ")
	)

	if useWhitelist {
		for _, ip := range s.Whitelist {
			if ip == addr || containsIp(ip, addr) {
				matched = true
				break
			}
		}
	}

	if !matched || len(auth) != 2 || auth[0] != "Bearer" || !s.checkApiKey(addr, auth[1]) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Denied request from ip %s\n", addr)
		return
	}

	switch r.Method {
	case "GET":
		var (
			path   string = strings.TrimLeft(r.URL.Path, "/")
			c      interface{}
			ok     bool
			params url.Values = r.URL.Query()
		)

		if strings.TrimRight(path, "/") == "bwvreload" {
			s.load()
			w.WriteHeader(http.StatusNoContent)
			return
		}

		log.Printf("[GET] %s %+v from %s\n", path, params, addr)
		if c, ok = bitw.Get(path); !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Path '%s' not found\n", path)
			return
		}

		var (
			value                       interface{}
			fieldKeys, propertyKeys     []string
			fieldValues, propertyValues map[string]interface{}
			useFields, useProperties    bool = false, false
		)

		if fields, ok := params["field"]; ok {
			useFields = true
			fieldKeys, fieldValues = s.parseFields(c.([]bitw.DecryptedCipher)[0], strings.Join(fields, ","))
		}

		if properties, ok := params["property"]; ok {
			useProperties = true
			propertyKeys, propertyValues = s.parseProperties(c.([]bitw.DecryptedCipher)[0], strings.Join(properties, ","))
		}

		if len(propertyKeys) == 0 && len(fieldKeys) > 0 {
			value = fieldValues
			if len(fieldKeys) == 1 {
				value = fieldValues[fieldKeys[0]]
			}
		} else if len(fieldKeys) == 0 && len(propertyKeys) > 0 {
			value = propertyValues
			if len(propertyKeys) == 1 {
				value = propertyValues[propertyKeys[0]]
			}
		}
		var length = len(append(propertyKeys, fieldKeys...))
		if (useFields || useProperties) && length == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Bad request for path %s\n", path)
			return
		}
		if length > 1 {
			if propertyValues == nil {
				propertyValues = make(map[string]interface{})
			}
			for k, v := range fieldValues {
				propertyValues[k] = v
			}
			value = propertyValues
		}

		if value != nil {
			c = value
			if length == 1 {
				c = map[string]interface{}{
					"value": value,
				}
			}
		}

		formatter := prettyjson.Formatter{
			DisabledColor:   true,
			Indent:          4,
			Newline:         "\n",
			StringMaxLength: 0,
		}
		s, e := formatter.Marshal(c)
		if e != nil {
			log.Fatal(e)
		}
		fmt.Fprint(w, string(s))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Invalid method")
	}
}

func (s *server) load() error {
	var configPath string = getConfigPath()
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	log.Printf("Loading config file %s\n", configPath)
	return yaml.Unmarshal(yamlFile, s)
}

func (s *server) listenAndServe() {
	var (
		listener net.Listener
		err      error
		port     int = DefaultPort
	)

	if err := s.load(); err != nil {
		log.Fatal(fmt.Sprintf("Invalid config file"), err)
	}

	sm := http.NewServeMux()
	sm.HandleFunc("/", s.getHttpPath)
	if s.Port == 0 {
		s.Port = DefaultPort
		s.save()
	}
	if listener, err = net.Listen("tcp4", fmt.Sprintf(":%d", s.Port)); err != nil {
		log.Fatal(err)
	}
	<-syncComplete
	if s.Cert != "" && s.Key != "" {
		log.Printf("Listening for secure connections on :%d (whitelist %+v)\n", port, s.Whitelist)
		log.Fatal(http.ServeTLS(listener, sm, s.Cert, s.Key))
	} else {
		if len(s.Whitelist) == 0 {
			log.Fatal("Cowardly - refusing to start unsecure credential server without a whitelist")
			return
		}
		log.Printf("Listening for unsecured connections on :%d (whitelist %+v)\n", port, s.Whitelist)
		log.Fatal(http.Serve(listener, sm))
	}
}
