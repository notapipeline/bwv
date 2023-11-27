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
package bitw

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hokaccha/go-prettyjson"
	"github.com/notapipeline/bwv/pkg/config"
)

const DefaultPort = 6278
const DURATION = 60

type HttpServer struct {
	c config.Config
}

func NewHttpServer() *HttpServer {
	return &HttpServer{
		c: *config.New(),
	}
}

func (s *HttpServer) IsSecure() (secure bool) {
	return s.c.IsSecure()
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

func (s *HttpServer) parseFields(c DecryptedCipher, fieldString string) (keys []string, values map[string]interface{}) {
	var (
		ok     bool
		fields = unique(strings.Split(fieldString, ","))
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

func (s *HttpServer) parseProperties(c DecryptedCipher, propertyString string) (keys []string, values map[string]interface{}) {
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

func (s *HttpServer) getHttpPath(w http.ResponseWriter, r *http.Request) {
	var (
		addr         string   = strings.Split(r.RemoteAddr, ":")[0]
		useWhitelist bool     = len(s.c.Whitelist) != 0
		matched      bool     = !useWhitelist || config.ContainsIp("127.0.0.0/24", addr)
		auth         []string = strings.Split(r.Header.Get("Authorization"), " ")
	)

	if useWhitelist {
		for _, ip := range s.c.Whitelist {
			if ip == addr || config.ContainsIp(ip, addr) {
				matched = true
				break
			}
		}
	}

	log.Println(addr, useWhitelist, matched)
	if !matched || len(auth) != 2 || auth[0] != "Bearer" || s.c.CheckApiKey(addr, auth[1]) {
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

		log.Printf("[GET] %s %+v from %s\n", path, params, addr)
		if c, ok = Get(path); !ok {
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
			fieldKeys, fieldValues = s.parseFields(c.([]DecryptedCipher)[0], strings.Join(fields, ","))
		}

		if properties, ok := params["property"]; ok {
			useProperties = true
			propertyKeys, propertyValues = s.parseProperties(c.([]DecryptedCipher)[0], strings.Join(properties, ","))
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

// storeToken stores a token sent via POST in the Authorization header
// The token is encrypted with the master password and stored in the
// config file for later verification.
func (s *HttpServer) storeToken(w http.ResponseWriter, r *http.Request) {
	var (
		addr  string   = strings.Split(r.RemoteAddr, ":")[0]
		auth  []string = strings.Split(r.Header.Get("Authorization"), " ")
		token string
		err   error
	)
	log.Printf("%q /storetoken called from %s", r.Method, addr)
	switch r.Method {
	case "POST":
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid method")
		return
	}
	// Verify the sent token can be decrypted with the known master password
	if token, err = DecryptToken(auth[1]); err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "bwv denied storeToken request from ip %s - %q\n", addr, err)
		return
	}

	s.c.ApiKeys[addr] = token
	w.WriteHeader(http.StatusNoContent)
	fmt.Fprintf(w, "bwv stored token for ip %s\n", addr)
}

func (s *HttpServer) reload(w http.ResponseWriter, r *http.Request) {
	if err := s.c.Load(config.ConfigModeServer); err != nil {
		log.Printf("error: invalid config file %q", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *HttpServer) kdf(w http.ResponseWriter, r *http.Request) {
	var (
		kdf []byte
		err error
	)
	if kdf, err = json.Marshal(secrets.KDF); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error": "%q"}`, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", kdf)
}

func (s *HttpServer) ListenAndServe() {
	var (
		secrets       map[string]string = config.GetSecretsFromUserEnvOrStore()
		listener      net.Listener
		err           error
		port          int = DefaultPort
		hashed        string
		useApiKeys    bool = secrets["BW_CLIENTID"] != "" && secrets["BW_CLIENTSECRET"] != ""
		loginResponse *LoginResponse
	)

	if hashed, err = Prelogin(secrets["BW_PASSWORD"], secrets["BW_EMAIL"]); err != nil {
		log.Fatal(err)
	}

	if useApiKeys {
		if loginResponse, err = ApiLogin(secrets["BW_CLIENTID"], secrets["BW_CLIENTSECRET"]); err != nil {
			log.Fatal(err)
		}
	} else {
		if loginResponse, err = UserLogin(hashed, secrets["BW_EMAIL"]); err != nil {
			log.Fatal(err)
		}
	}

	// force sync every DURATION seconds
	go func() {
		for {
			log.Println("Syncing...")
			syncStore(loginResponse)
			<-time.After(DURATION * time.Second)
		}
	}()

	if err := s.c.Load(config.ConfigModeServer); err != nil {
		log.Fatalf("Invalid config file: %q", err)
	}

	sm := http.NewServeMux()
	sm.HandleFunc("/api/v1/kdf", s.kdf)
	sm.HandleFunc("/api/v1/reload", s.reload)
	sm.HandleFunc("/api/v1/storetoken", s.storeToken)
	sm.HandleFunc("/", s.getHttpPath)
	if s.c.Port == 0 {
		s.c.Port = DefaultPort
		if err = s.c.Save(); err != nil {
			log.Fatal(err)
		}
	}
	if listener, err = net.Listen("tcp4", fmt.Sprintf(":%d", s.c.Port)); err != nil {
		log.Fatal(err)
	}

	if s.c.IsSecure() {
		log.Printf("Listening for secure connections on :%d (whitelist %+v)\n", port, s.c.Whitelist)
		log.Fatal(http.ServeTLS(listener, sm, s.c.Cert, s.c.Key))
	} else {
		if len(s.c.Whitelist) == 0 {
			log.Fatal("Cowardly - refusing to start unsecure credential server without a whitelist")
			return
		}
		log.Printf("Listening for unsecured connections on :%d (whitelist %+v)\n", port, s.c.Whitelist)
		log.Fatal(http.Serve(listener, sm))
	}
}
