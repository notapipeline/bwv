/*
 *   Copyright 2025 Martin Proffitt <mproffitt@choclab.net>
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

// Package bwv is a client for a running bwv server, for applications that want
// to read secrets from the local vault daemon without reimplementing the
// handshake.
//
// The server authenticates a caller with a token encrypted under the user's
// master password, which means fetching the server's KDF parameters first. This
// package owns that exchange: construct a Client and the credentials are
// resolved from the environment or the platform credential store on the first
// request.
//
//	c, err := bwv.NewClient(bwv.Options{})
//	if err != nil {
//	        return err
//	}
//
//	values, err := c.GetProperties(ctx, "choclab/customers/giantswarm", "company")
package bwv

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

// ErrNoSelection is returned when none of the requested names exist on the
// matched item. The server answers such a request with the whole item -
// attachments included - and this package will not pass that off as the values
// that were asked for.
var ErrNoSelection = errors.New("bwv: none of the requested values exist on the matched item")

// ErrMultipleItems is returned when a value selection matches more than one
// item. Use Get for wildcard paths.
var ErrMultipleItems = errors.New("bwv: path matched more than one item")

// getSecrets is indirected for testing.
var getSecrets = tools.GetSecretsFromUserEnvOrStore

// Options configures a Client. The zero value talks to a bwv server on
// localhost:6277, taking anything it needs from the client config file and the
// credential store.
type Options struct {
	// Server is the address of the bwv server. Defaults to the client config's
	// address, then "localhost".
	Server string

	// Port the bwv server listens on. Defaults to the client config's port,
	// then bitw.DefaultPort.
	Port int

	// Token is the API token for this address. When empty it is taken from
	// BW_CLIENTSECRET, then BW_PASSWORD, then the client config.
	Token string

	// SkipVerify disables verification of the server's TLS certificate.
	SkipVerify bool

	// Timeout bounds a single request. Defaults to 10s.
	Timeout time.Duration

	// Retry is how long to keep retrying a failed request. Zero - the default -
	// attempts each request once, which is what you want against a daemon that
	// is either up or is not. The bwv CLI sets this so it can ride out a server
	// that is still starting.
	Retry time.Duration

	// HTTP replaces the client built from Timeout, Retry and SkipVerify. Set it
	// when the caller already owns a transport, or to drive the client from a
	// test double.
	HTTP transport.HttpClient
}

// Client reads secrets from a bwv server.
type Client struct {
	opts Options
	http transport.HttpClient
	base string

	// The encrypted token costs a full KDF derivation, so it is built once on
	// the first request rather than in NewClient - constructing a client must
	// not block on the daemon being up.
	once  sync.Once
	token string
	err   error
}

// NewClient returns a Client for the bwv server described by o, filling any
// blanks from the client config file.
func NewClient(o Options) (*Client, error) {
	if o.Server == "" || o.Port == 0 || o.Token == "" {
		if err := applyConfig(&o); err != nil {
			return nil, err
		}
	}

	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}

	httpClient := o.HTTP
	if httpClient == nil {
		httpClient = transport.NewHttpClient(
			&tls.Config{InsecureSkipVerify: o.SkipVerify}, //nolint:gosec // opt-in, off by default
			o.Timeout, o.Retry)
	}

	return &Client{
		opts: o,
		base: fmt.Sprintf("https://%s:%d", o.Server, o.Port),
		http: httpClient,
	}, nil
}

// applyConfig fills the address, port and token from the client config file. A
// missing config file is not an error: the defaults and the credential store
// cover the common case of a server on localhost.
func applyConfig(o *Options) error {
	c := config.New()
	if err := c.Load(config.ConfigModeClient); err != nil {
		return fmt.Errorf("bwv: could not load client config: %w", err)
	}

	if o.Server == "" {
		if o.Server = c.Address; o.Server == "" {
			o.Server = "localhost"
		}
	}

	if o.Port == 0 {
		if o.Port = c.Port; o.Port == 0 {
			o.Port = bitw.DefaultPort
		}
	}

	if o.Token == "" {
		o.Token = c.Token
	}
	return nil
}

// Get returns every item matching path, decrypted in full. path may contain the
// wildcards the server understands ("*", "folder/*", "*/name").
func (c *Client) Get(ctx context.Context, path string) ([]bitw.DecryptedCipher, error) {
	message, err := c.Raw(ctx, path, "")
	if err != nil {
		return nil, err
	}

	var ciphers []bitw.DecryptedCipher
	if err := remarshal(message.Message, &ciphers); err != nil {
		return nil, fmt.Errorf("bwv: unexpected response for %q: %w", path, err)
	}
	return ciphers, nil
}

// GetProperties returns the named top level attributes of the item at path -
// username, password, notes, totp, or any identity attribute.
func (c *Client) GetProperties(ctx context.Context, path string, names ...string) (map[string]string, error) {
	return c.values(ctx, path, "properties", names)
}

// GetFields returns the named custom fields of the item at path.
func (c *Client) GetFields(ctx context.Context, path string, names ...string) (map[string]string, error) {
	return c.values(ctx, path, "fields", names)
}

// GetAttachments returns the named attachments of the item at path, decoded.
func (c *Client) GetAttachments(ctx context.Context, path string, names ...string) (map[string][]byte, error) {
	values, err := c.values(ctx, path, "attachments", names)
	if err != nil {
		return nil, err
	}

	var decoded = make(map[string][]byte, len(values))
	for name, value := range values {
		b, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("bwv: attachment %q is not base64: %w", name, err)
		}
		decoded[name] = b
	}
	return decoded, nil
}

// Raw returns the server's response for path and query verbatim. The response
// shape varies with what was asked for, so prefer Get, GetProperties,
// GetFields or GetAttachments; this exists for the CLI, which renders the
// server's shapes as documented.
func (c *Client) Raw(ctx context.Context, path, query string) (types.SecretResponse, error) {
	var response types.SecretResponse

	token, err := c.authToken(ctx)
	if err != nil {
		return response, err
	}

	var address = c.base + "/" + strings.TrimLeft(path, "/")
	if query != "" {
		address += "?" + query
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return response, err
	}

	ctx = context.WithValue(ctx, transport.AuthToken{}, token)
	if err := c.http.DoWithBackoff(ctx, req, &response); err != nil {
		return response, err
	}
	return response, nil
}

// values asks for a single selection kind and returns it as a flat map.
//
// The server collapses a response carrying exactly one value to {"value": x},
// which loses the name it belongs to, and answers a selection that matches
// nothing with the entire item. Both are avoided by always asking for the
// item's name alongside the real selection: the response then always carries at
// least two values, so it always comes back keyed, and an empty result after
// dropping the name means nothing matched.
func (c *Client) values(ctx context.Context, path, kind string, names []string) (map[string]string, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("bwv: no %s requested for %q", kind, path)
	}

	query := url.Values{
		kind:         {strings.Join(names, ",")},
		"properties": {"name"},
	}
	if kind == "properties" {
		query.Set("properties", strings.Join(append([]string{"name"}, names...), ","))
	}

	response, err := c.Raw(ctx, path, query.Encode())
	if err != nil {
		return nil, err
	}

	values, err := flatten(response.Message)
	if err != nil {
		return nil, err
	}

	if !contains(names, "name") {
		delete(values, "name")
	}

	if len(values) == 0 {
		return nil, ErrNoSelection
	}
	return values, nil
}

// flatten converts the server's keyed response into a map of strings, rejecting
// the shapes that mean the request did not narrow to one item.
func flatten(message any) (map[string]string, error) {
	fields, ok := message.(map[string]any)
	if !ok {
		// An array is the server returning whole items, which it does when the
		// selection matched nothing at all.
		return nil, ErrNoSelection
	}

	var values = make(map[string]string, len(fields))
	for k, v := range fields {
		switch v := v.(type) {
		case string:
			values[k] = v
		case map[string]any:
			// Keyed by cipher id: the path matched more than one item.
			return nil, ErrMultipleItems
		default:
			values[k] = fmt.Sprint(v)
		}
	}
	return values, nil
}

// Token returns the bearer token this client authenticates with: the API token
// encrypted with a key derived from the master password, which is what the
// server checks. Get and the rest apply it themselves; this is for callers
// driving the server's admin endpoints directly.
func (c *Client) Token(ctx context.Context) (string, error) {
	return c.authToken(ctx)
}

// authToken returns the bearer token for the server, deriving it once.
func (c *Client) authToken(ctx context.Context) (string, error) {
	c.once.Do(func() { c.token, c.err = c.encryptToken(ctx) })
	return c.token, c.err
}

// encryptToken encrypts the API token with a key derived from the master
// password, which is what the server checks it against. The KDF parameters have
// to come from the server so both sides derive the same key.
func (c *Client) encryptToken(ctx context.Context) (string, error) {
	var secrets = getSecrets(false)

	password, email := secrets["BW_PASSWORD"], secrets["BW_EMAIL"]
	if len(password) == 0 || len(email) == 0 {
		return "", errors.New("bwv: no Bitwarden credentials available to authenticate with the server")
	}

	token := c.opts.Token
	if token == "" {
		if token = string(secrets["BW_CLIENTSECRET"]); token == "" {
			token = string(password)
		}
	}

	var kdf types.KDFInfo
	if err := c.http.Get(ctx, c.base+"/api/v1/kdf", &kdf); err != nil {
		return "", fmt.Errorf("bwv: could not read kdf info from the server: %w", err)
	}

	encrypted, err := crypto.Encrypt(password, string(email), token, kdf)
	if err != nil {
		return "", fmt.Errorf("bwv: could not encrypt the api token: %w", err)
	}
	return encrypted, nil
}

// remarshal moves a decoded any into a typed value.
func remarshal(src, dst any) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
