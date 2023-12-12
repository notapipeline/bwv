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
	"runtime/debug"
	"strings"

	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/types"
)

const DefaultPort = 6277

type HttpServer struct {
	config *config.Config
	Bwv    *Bwv
}

func NewHttpServer(config *config.Config) *HttpServer {
	return &HttpServer{
		config: config,
		Bwv:    NewBwv(),
	}
}

func (s *HttpServer) writeResponseError(w *http.ResponseWriter, message string, code int, err error) {
	var msg string = fmt.Sprintf("error: %d : %q", code, message)
	if s.config.Server.Debug {
		debug.PrintStack()
	}

	if err != nil {
		msg += fmt.Sprintf(" : %q", err)
	}

	log.Println(msg)
	// There has to be a cleaner way of managing this...
	message = strings.ReplaceAll(message, `"`, ``)
	message = strings.ReplaceAll(message, `\`, ``)
	var b []byte
	if b, err = json.Marshal(map[string]string{
		"message": message,
	}); err != nil {
		log.Println(err)
	}

	(*w).WriteHeader(code)
	fmt.Fprint(*w, string(b))
}

func (s *HttpServer) IsSecure() (secure bool) {
	return s.config.IsSecure()
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

func (s *HttpServer) parseFields(c DecryptedCipher, fields []string) (values map[string]interface{}) {
	var ok bool
	fields = unique(fields)
	values = make(map[string]interface{})

	for _, f := range fields {
		var v interface{}
		if v, ok = c.Fields[f]; ok && v != "" {
			values[f] = v
		}
	}
	return
}

func (s *HttpServer) parseProperties(c DecryptedCipher, properties []string) (values map[string]interface{}) {
	properties = unique(properties)
	values = make(map[string]interface{})

	for _, p := range properties {
		var v interface{}
		if v = c.Get(p); v != "" && v != nil {
			values[p] = v
		}
	}
	return
}

func (s *HttpServer) parseAttachments(c DecryptedCipher, attachments []string) (values map[string]interface{}) {
	attachments = unique(attachments)
	values = make(map[string]interface{})

	for _, a := range attachments {
		var v interface{}
		if v = c.Attachments[a]; v != "" {
			values[a] = v
		}
	}
	return
}

func (s *HttpServer) checkWhiteList(w http.ResponseWriter, addr string) bool {
	if tools.IsMachineNetwork(addr) {
		return true
	}

	var (
		useWhitelist bool = len(s.config.Server.Whitelist) != 0
		matched      bool = false
	)

	if useWhitelist {
		for _, ip := range s.config.Server.Whitelist {
			if ip == addr || tools.ContainsIp(ip, addr) {
				matched = true
				break
			}
		}
	}

	return matched
}

func (s *HttpServer) validate(w http.ResponseWriter, r *http.Request) bool {
	var (
		addr  string   = strings.Split(r.RemoteAddr, ":")[0]
		auth  []string = strings.Split(r.Header.Get("Authorization"), " ")
		err   error
		token []byte
	)

	if addr == "" {
		s.writeResponseError(&w, "bwv denied the request", http.StatusBadRequest, nil)
		return false
	}

	if !s.checkWhiteList(w, addr) {
		err = fmt.Errorf("address %s not in whitelist", addr)
		s.writeResponseError(&w, "bwv denied the request", http.StatusForbidden, err)
		return false
	}

	if len(auth) != 2 || auth[0] != "Bearer" || auth[1] == "" {
		err = fmt.Errorf("invalid authorization header %+v", auth)
		s.writeResponseError(&w, "bwv denied the request", http.StatusUnauthorized, err)
		return false
	}

	// Verify the sent token can be decrypted with the known master password
	var handshakeToken types.CipherString = types.CipherString{}
	if err = handshakeToken.UnmarshalText([]byte(auth[1])); err != nil {
		token = []byte(auth[1]) // this will be a plaintext token
	} else {
		k, m, _ := cache.MasterPasswordKeyMac()
		if token, err = crypto.DecryptWith(handshakeToken, k, m); err != nil {
			s.writeResponseError(&w, "bwv denied the request", http.StatusForbidden, err)
			return false
		}
	}

	switch r.URL.Path {
	case "/storetoken":
		return true
	}

	log.Println("Checking API key for", addr)
	if !s.config.CheckApiKey(addr, string(token)) {
		if handshakeToken, err = s.Bwv.Secrets.Encrypt(token); err != nil {
			s.writeResponseError(&w, "bwv denied the request", http.StatusUnauthorized, err)
			return false
		}

		log.Println("checking against whitelist encrypted tokens")
		if !s.config.CheckApiKey(addr, handshakeToken.String()) {
			s.writeResponseError(&w, "bwv denied the request", http.StatusUnauthorized, err)
			return false
		}
	}

	return true
}

func (s *HttpServer) getPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.writeResponseError(&w, "bwv denied the request - invalid method", http.StatusMethodNotAllowed, nil)
		return
	}

	var (
		addr                                          string = strings.Split(r.RemoteAddr, ":")[0]
		path                                          string = strings.TrimLeft(r.URL.Path, "/")
		secret                                        interface{}
		ok                                            bool
		values                                        map[string]interface{} = make(map[string]interface{})
		fieldValues, propertyValues, attachmentValues map[string]interface{}
		params                                        map[string][]string = make(map[string][]string)
	)

	var urlValues url.Values = r.URL.Query()
	for k, v := range urlValues {
		params[k] = strings.Split(v[0], ",")
	}

	if !s.validate(w, r) {
		return
	}

	if err := s.Bwv.Sync(); err != nil {
		s.writeResponseError(&w, "bwv denied the request", http.StatusInternalServerError, err)
		return
	}
	log.Printf("[GET] %s %+v from %s\n", path, r.URL.Query(), addr)
	if secret, ok = s.Bwv.Get(path); !ok {
		s.writeResponseError(&w, fmt.Sprintf("Path '%s' not found", path), http.StatusNotFound, nil)
		return
	}

	// TODO: Currently these only accept the first cipher in the array
	//       It would be better if this iterated over the list of ciphers
	//       and returned the requested fields for each cipher - if there is only
	//       one cipher then it should return the fields for that cipher or
	//       `value: <value>` if there is only one field on one cipher requested.

	var responseLen = 0
	log.Printf("checking for requested fields")
	if fields, ok := params["fields"]; ok && len(fields) > 0 {
		fieldValues = s.parseFields(secret.([]DecryptedCipher)[0], fields)
		for k, v := range fieldValues {
			values[k] = v
			responseLen++
		}
	}

	log.Printf("checking for requested properties")
	if properties, ok := params["properties"]; ok && len(properties) > 0 {
		propertyValues = s.parseProperties(secret.([]DecryptedCipher)[0], properties)
		for k, v := range propertyValues {
			values[k] = v
			responseLen++
		}
	}

	log.Printf("checking for requested attachments")
	if attachments, ok := params["attachments"]; ok && len(attachments) > 0 {
		attachmentValues = s.parseAttachments(secret.([]DecryptedCipher)[0], attachments)
		for k, v := range attachmentValues {
			values[k] = v
			responseLen++
		}
	}

	switch responseLen {
	case 0:
	case 1:
		for k := range values {
			secret = map[string]interface{}{
				"value": values[k],
			}
		}
	default:
		secret = values
	}

	var secretResponse types.SecretResponse = types.SecretResponse{
		Message: secret,
	}

	var (
		b   []byte
		err error
	)
	if b, err = json.Marshal(secretResponse); err != nil {
		s.writeResponseError(&w, fmt.Sprintf("error: %q", err), http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(b))
}

// revokeToken revokes a token sent via POST in the Authorization header
func (s *HttpServer) revokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.writeResponseError(&w, "bwv denied the request", http.StatusMethodNotAllowed, nil)
		return
	}

	if !s.validate(w, r) {
		return
	}

	var (
		err  error
		addr map[string]string
	)

	if err = json.NewDecoder(r.Body).Decode(&addr); err != nil {
		s.writeResponseError(&w, "bwv denied the request", http.StatusInternalServerError, err)
		return
	}

	if err = s.config.DeleteApiKey(addr["address"]); err != nil {
		s.writeResponseError(&w, "bwv denied the request", http.StatusInternalServerError, err)
		return
	}

	if err = s.config.Save(); err != nil {
		s.writeResponseError(&w, "bwv denied the request", http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// storeToken stores a token sent via POST in the Authorization header
// The token is encrypted with the master password and stored in the
// config file for later verification.
func (s *HttpServer) storeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.writeResponseError(&w, "bwv denied the request", http.StatusMethodNotAllowed, nil)
		return
	}

	var (
		addr           string = strings.Split(r.RemoteAddr, ":")[0]
		token          string
		encryptedToken types.CipherString
		err            error
	)

	if !s.validate(w, r) {
		return
	}

	token = s.Bwv.CreateToken()
	if encryptedToken, err = s.Bwv.Secrets.Encrypt([]byte(token)); err != nil {
		s.writeResponseError(&w, "bwv denied the request", http.StatusInternalServerError, err)
		return
	}

	if err = s.config.SetApiKey(addr, encryptedToken); err != nil {
		s.writeResponseError(&w, "bwv denied the request", http.StatusBadRequest, err)
		return
	}

	var b []byte
	if b, err = json.Marshal(struct {
		Token string `json:"token"`
	}{
		Token: token,
	}); err != nil {
		s.writeResponseError(&w, "bwv denied the request", http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(b))
}

// reload the config file
func (s *HttpServer) reload(w http.ResponseWriter, r *http.Request) {
	if err := s.config.Load(config.ConfigModeServer); err != nil {
		log.Printf("error: invalid config file %q", err)
		s.writeResponseError(&w, "an internal server error has occurred - please try again later", http.StatusInternalServerError, err)
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
	if kdf, err = json.Marshal(s.Bwv.Secrets.KDF); err != nil {
		s.writeResponseError(&w, fmt.Sprintf("error: %q", err), http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", kdf)
}

// ListenAndServe starts the HTTP server and listens for requests
func (s *HttpServer) ListenAndServe(cmdConfig *types.ServeCmd, autoload *chan bool) (err error) {
	var (
		listener net.Listener
		port     int = DefaultPort
		server   *http.ServeMux
	)

	if err := s.config.Load(config.ConfigModeServer); err != nil {
		log.Fatalf("Invalid config file: %q", err)
	}

	s.config.MergeServerConfig(cmdConfig)
	if s.config.Server.Port != 0 {
		port = s.config.Server.Port
	}

	if !s.IsSecure() && len(s.config.Server.Whitelist) == 0 {
		return fmt.Errorf("Cowardly - refusing to start unsecure credential server without a whitelist")
	}

	server = http.NewServeMux()
	server.HandleFunc("/api/v1/kdf", s.kdf)
	server.HandleFunc("/api/v1/reload", s.reload)
	server.HandleFunc("/api/v1/storetoken", s.storeToken)
	server.HandleFunc("/api/v1/revoketoken", s.revokeToken)
	server.HandleFunc("/", s.getPath)

	log.Printf("Starting server on port %d", port)
	if listener, err = net.Listen("tcp4", fmt.Sprintf("%s:%d", s.config.Server.Server, port)); err != nil {
		log.Fatal(err)
	}

	if autoload != nil {
		s.Bwv.autoload = autoload
	}

	s.Bwv.Setup()
	if s.config.IsSecure() {
		log.Printf("Listening for secure connections on :%d (whitelist %+v)\n", port, s.config.Server.Whitelist)
		err = http.ServeTLS(listener, server, s.config.Server.Cert, s.config.Server.Key)
		return
	}

	log.Printf("Listening for unsecured connections on :%d (whitelist %+v)\n", port, s.config.Server.Whitelist)
	err = http.Serve(listener, server)
	return err
}
