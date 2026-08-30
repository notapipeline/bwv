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
package bwv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/notapipeline/bwv/pkg/types"
)

// newTestClient stands up a fake bwv server that serves the kdf endpoint and
// hands every other request to handler, and returns a Client pointed at it.
// requests records the query string of each secret request so tests can assert
// on what the client actually asked for.
func newTestClient(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*Client, *[]url.Values) {
	t.Helper()

	og := getSecrets
	getSecrets = func(bool) map[string][]byte {
		return map[string][]byte{
			"BW_PASSWORD": []byte("masterpw"),
			"BW_EMAIL":    []byte("email@example.com"),
		}
	}
	t.Cleanup(func() { getSecrets = og })

	var requests []url.Values
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/kdf" {
			// A low iteration count keeps the key derivation cheap; the
			// client only has to agree with the server, not be slow.
			_ = json.NewEncoder(w).Encode(types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 1000})
			return
		}

		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") || len(auth) < 10 {
			t.Errorf("request for %s carried no bearer token (got %q)", r.URL.Path, auth)
		}

		requests = append(requests, r.URL.Query())
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(Options{Server: u.Hostname(), Port: port, Token: "testtoken", SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return c, &requests
}

func respond(t *testing.T, w http.ResponseWriter, message any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(types.SecretResponse{Message: message}); err != nil {
		t.Fatal(err)
	}
}

func TestGetProperties(t *testing.T) {
	c, requests := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		respond(t, w, map[string]any{
			"name":      "giantswarm",
			"company":   "Giant Swarm GmbH",
			"firstname": "Oliver",
		})
	})

	got, err := c.GetProperties(context.Background(), "choclab/customers/giantswarm", "company", "firstname")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{"company": "Giant Swarm GmbH", "firstname": "Oliver"}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	// name is asked for so the server never collapses the response to
	// {"value": x}, but it must not leak into the result.
	props := (*requests)[0].Get("properties")
	if !strings.Contains(props, "name") {
		t.Errorf("properties %q should have carried name", props)
	}
	if _, ok := got["name"]; ok {
		t.Error("name should have been dropped from the result")
	}
}

// Asking for a property the item does not have must not hand back the whole
// item, which is what the server returns in that case.
func TestGetPropertiesNoSelection(t *testing.T) {
	for _, tt := range []struct {
		name    string
		message any
	}{
		{"only the name comes back", map[string]any{"name": "id_rsa.giantswarm"}},
		{"server falls back to whole items", []any{map[string]any{
			"name":        "id_rsa.giantswarm",
			"attachments": map[string]any{"id_rsa.giantswarm": "c3NoLXByaXZhdGUta2V5"},
		}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				respond(t, w, tt.message)
			})

			got, err := c.GetProperties(context.Background(), "*/id_rsa.giantswarm", "notes")
			if !errors.Is(err, ErrNoSelection) {
				t.Fatalf("err = %v, want ErrNoSelection", err)
			}
			if got != nil {
				t.Errorf("got %+v, want nothing", got)
			}
		})
	}
}

func TestGetPropertiesMultipleItems(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		respond(t, w, map[string]any{
			"11111111-1111-1111-1111-111111111111": map[string]any{"name": "one", "username": "a"},
			"22222222-2222-2222-2222-222222222222": map[string]any{"name": "two", "username": "b"},
		})
	})

	if _, err := c.GetProperties(context.Background(), "choclab/*", "username"); !errors.Is(err, ErrMultipleItems) {
		t.Fatalf("err = %v, want ErrMultipleItems", err)
	}
}

func TestGetReturnsTypedCiphers(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		respond(t, w, []any{map[string]any{
			"id":       "33333333-3333-3333-3333-333333333333",
			"name":     "giantswarm",
			"type":     4,
			"notes":    "a note",
			"identity": map[string]any{"company": "Giant Swarm GmbH"},
		}})
	})

	got, err := c.Get(context.Background(), "choclab/customers/giantswarm")
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 {
		t.Fatalf("got %d ciphers, want 1", len(got))
	}
	if got[0].Name != "giantswarm" || got[0].Type != 4 {
		t.Errorf("got %+v, want the giantswarm identity", got[0])
	}
	if got[0].Notes != "a note" {
		t.Errorf("Notes = %q, want %q", got[0].Notes, "a note")
	}
	if got[0].Identity["company"] != "Giant Swarm GmbH" {
		t.Errorf("identity = %+v, want the company", got[0].Identity)
	}
}

func TestGetAttachmentsDecodes(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		respond(t, w, map[string]any{
			"name":       "some-item",
			"secret.txt": base64.StdEncoding.EncodeToString([]byte("hello")),
		})
	})

	got, err := c.GetAttachments(context.Background(), "example/test", "secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got["secret.txt"]) != "hello" {
		t.Errorf("got %q, want %q", got["secret.txt"], "hello")
	}
}

func TestNoNamesRequested(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should have been made")
	})

	if _, err := c.GetFields(context.Background(), "example/test"); err == nil {
		t.Fatal("expected an error when no fields are named")
	}
}

// The credential store being empty must fail loudly rather than sending an
// unauthenticated request.
func TestMissingCredentials(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should have been made")
	})
	getSecrets = func(bool) map[string][]byte { return map[string][]byte{} }

	if _, err := c.GetProperties(context.Background(), "example/test", "username"); err == nil {
		t.Fatal("expected an error with no credentials available")
	}
}
