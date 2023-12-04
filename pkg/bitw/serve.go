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

	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/types"
)

const DefaultPort = 6278

type HttpServer struct {
	c *config.Config
}

func NewHttpServer() *HttpServer {
	return &HttpServer{
		c: config.New(),
	}
}

func (s *HttpServer) writeResponseError(w *http.ResponseWriter, message string, code int) (err error) {
	// There has to be a cleaner way of managing this...
	message = strings.ReplaceAll(message, `"`, ``)
	message = strings.ReplaceAll(message, `\`, ``)
	var b []byte
	if b, err = json.Marshal(map[string]string{
		"message": message,
	}); err != nil {
		return
	}

	(*w).WriteHeader(code)
	fmt.Fprint(*w, string(b))
	return
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

func (s *HttpServer) getPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		_ = s.writeResponseError(&w, "bwv denied get request - invalid method", http.StatusMethodNotAllowed)
		return
	}

	var (
		addr                        string   = strings.Split(r.RemoteAddr, ":")[0]
		useWhitelist                bool     = len(s.c.Server.Whitelist) != 0
		matched                     bool     = !useWhitelist || tools.ContainsIp("127.0.0.0/24", addr)
		auth                        []string = strings.Split(r.Header.Get("Authorization"), " ")
		path                        string   = strings.TrimLeft(r.URL.Path, "/")
		secret                      interface{}
		ok                          bool
		params                      url.Values = r.URL.Query()
		value                       interface{}
		fieldKeys, propertyKeys     []string
		fieldValues, propertyValues map[string]interface{}
	)

	if addr == "" {
		_ = s.writeResponseError(&w, "bwv denied get request - no ip address", http.StatusBadRequest)
		return
	}

	if useWhitelist {
		for _, ip := range s.c.Server.Whitelist {
			if ip == addr || tools.ContainsIp(ip, addr) {
				matched = true
				break
			}
		}
	}

	if !matched {
		_ = s.writeResponseError(&w, "bwv denied get request", http.StatusForbidden)
		return
	}

	log.Println(addr, useWhitelist, matched)
	if len(auth) != 2 || auth[0] != "Bearer" || s.c.CheckApiKey(addr, auth[1]) {
		_ = s.writeResponseError(&w, "bwv denied get request - missing or invalid token", http.StatusUnauthorized)
		return
	}

	syncStore(loginResponse)
	log.Printf("[GET] %s %+v from %s\n", path, params, addr)
	if secret, ok = Get(path); !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Path '%s' not found\n", path)
		return
	}

	log.Printf("Secret found, checking for requested fields")
	if fields, ok := params["fields"]; ok && len(fields) > 0 {
		fieldKeys, fieldValues = s.parseFields(secret.([]DecryptedCipher)[0], strings.Join(fields, ","))
	}

	if properties, ok := params["properties"]; ok && len(properties) > 0 {
		propertyKeys, propertyValues = s.parseProperties(secret.([]DecryptedCipher)[0], strings.Join(properties, ","))
	}

	// If we're only requesting a single property or field, return only the
	// value of that as `{"value": "foo"}` otherwise we'll return the entire
	// set of properties and fields as `{"value": {"foo": "bar", "baz": "qux"}}`
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
		secret = value
		if length == 1 {
			secret = map[string]interface{}{
				"value": value,
			}
		}
	}

	var secretResponse types.SecretResponse = types.SecretResponse{
		Message: secret,
	}

	var (
		b   []byte
		err error
	)
	if b, err = json.Marshal(secretResponse); err != nil {
		_ = s.writeResponseError(&w, fmt.Sprintf("error: %q", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(b))
}

// storeToken stores a token sent via POST in the Authorization header
// The token is encrypted with the master password and stored in the
// config file for later verification.
func (s *HttpServer) storeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		_ = s.writeResponseError(&w, "bwv denied storeToken request - invalid method", http.StatusMethodNotAllowed)
		return
	}

	var (
		addr  string   = strings.Split(r.RemoteAddr, ":")[0]
		auth  []string = strings.Split(r.Header.Get("Authorization"), " ")
		token string
		err   error
	)

	if addr == "" {
		_ = s.writeResponseError(&w, "bwv denied storeToken request - no ip address", http.StatusBadRequest)
		return
	}

	if len(auth) != 2 || auth[0] != "Bearer" {
		_ = s.writeResponseError(&w, "bwv denied storeToken request - missing or invalid token", http.StatusUnauthorized)
		return
	}

	// Verify the sent token can be decrypted with the known master password
	if _, err = DecryptToken(auth[1]); err != nil {
		_ = s.writeResponseError(&w, fmt.Sprintf("bwv denied storeToken request from ip %s - %q", addr, err.Error()), http.StatusForbidden)
		return
	}

	if token, err = s.c.AddApiKey(addr); err != nil {
		_ = s.writeResponseError(&w, fmt.Sprintf("bwv denied storeToken request from ip %s - %q", addr, err.Error()), http.StatusInternalServerError)
		return
	}

	if err = s.c.Save(); err != nil {
		_ = s.writeResponseError(&w, fmt.Sprintf("bwv denied storeToken request from ip %s - %q", addr, err.Error()), http.StatusInternalServerError)
		return
	}

	var b []byte
	if b, err = json.Marshal(struct {
		Token string `json:"token"`
	}{
		Token: token,
	}); err != nil {
		_ = s.writeResponseError(&w, fmt.Sprintf("bwv denied storeToken request from ip %s - %q", addr, err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(b))
}

// reload the config file
func (s *HttpServer) reload(w http.ResponseWriter, r *http.Request) {
	if err := s.c.Load(config.ConfigModeServer); err != nil {
		log.Printf("error: invalid config file %q", err)
		err = s.writeResponseError(&w, "an internal server error has occurred - please try again later", http.StatusInternalServerError)
		if err != nil {
			log.Printf("error: %q", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// get the key derivation function used to encrypt the master password
// this is not the same as the function used to obtain kdf from bitwarden
// but is made available for the client to be able to send tokens to the
// server for storage and revokation.
func (s *HttpServer) kdf(w http.ResponseWriter, r *http.Request) {
	var (
		kdf []byte
		err error
	)
	if kdf, err = json.Marshal(secrets.KDF); err != nil {
		_ = s.writeResponseError(&w, fmt.Sprintf("error: %q", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", kdf)
}

// ListenAndServe starts the HTTP server and listens for requests
func (s *HttpServer) ListenAndServe(cmdConfig types.ServeCmd) (err error) {
	var (
		listener net.Listener
		port     int = DefaultPort
		server   *http.ServeMux
	)

	if err := s.c.Load(config.ConfigModeServer); err != nil {
		log.Fatalf("Invalid config file: %q", err)
	}
	s.c.MergeServerConfig(cmdConfig)

	server = http.NewServeMux()
	server.HandleFunc("/api/v1/kdf", s.kdf)
	server.HandleFunc("/api/v1/reload", s.reload)
	server.HandleFunc("/api/v1/storetoken", s.storeToken)
	server.HandleFunc("/", s.getPath)

	log.Printf("Starting server on port %d\n", s.c.Server.Port)
	if s.c.Server.Port == 0 {
		s.c.Server.Port = DefaultPort
		if err = s.c.Save(); err != nil {
			log.Fatal(err)
		}
	}

	if listener, err = net.Listen("tcp4", fmt.Sprintf(":%d", s.c.Server.Port)); err != nil {
		log.Fatal(err)
	}

	if !s.IsSecure() && len(s.c.Server.Whitelist) == 0 {
		return fmt.Errorf("Cowardly - refusing to start unsecure credential server without a whitelist")
	}

	setup()
	if s.c.IsSecure() {
		log.Printf("Listening for secure connections on :%d (whitelist %+v)\n", port, s.c.Server.Whitelist)
		err = http.ServeTLS(listener, server, s.c.Server.Cert, s.c.Server.Key)
		return
	}

	log.Printf("Listening for unsecured connections on :%d (whitelist %+v)\n", port, s.c.Server.Whitelist)
	err = http.Serve(listener, server)
	return err
}
