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
package bitw

import (
	"testing"
	"time"

	"github.com/notapipeline/bwv/pkg/transport"
)

func TestCredentialMode(t *testing.T) {
	tests := []struct {
		name      string
		secrets   map[string][]byte
		wantApi   bool
		wantReady bool
	}{
		{
			name:      "empty store (kwallet locked at boot)",
			secrets:   map[string][]byte{"BW_CLIENTID": {}, "BW_CLIENTSECRET": {}, "BW_PASSWORD": {}, "BW_EMAIL": {}},
			wantApi:   false,
			wantReady: false,
		},
		{
			name:      "nil values",
			secrets:   map[string][]byte{},
			wantApi:   false,
			wantReady: false,
		},
		{
			name:      "api credentials present",
			secrets:   map[string][]byte{"BW_CLIENTID": []byte("id"), "BW_CLIENTSECRET": []byte("secret")},
			wantApi:   true,
			wantReady: true,
		},
		{
			name:      "user credentials present",
			secrets:   map[string][]byte{"BW_PASSWORD": []byte("pw"), "BW_EMAIL": []byte("me@example.com")},
			wantApi:   false,
			wantReady: true,
		},
		{
			name:      "partial api credentials fall back to not-ready",
			secrets:   map[string][]byte{"BW_CLIENTID": []byte("id"), "BW_CLIENTSECRET": {}},
			wantApi:   false,
			wantReady: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotApi, gotReady := credentialMode(tt.secrets)
			if gotApi != tt.wantApi || gotReady != tt.wantReady {
				t.Errorf("credentialMode() = (api=%v, ready=%v), want (api=%v, ready=%v)",
					gotApi, gotReady, tt.wantApi, tt.wantReady)
			}
		})
	}
}

// TestApiLoginDoesNotRetryPermanentError proves that a 4xx (e.g. blank
// credentials from a locked store) is not retried. The mock is primed with a
// single 400 response: if ApiLogin retried, the second call would drain the
// (now empty) response slice and return a spurious success, so a non-nil error
// here can only mean the loop broke on the permanent error.
func TestApiLoginDoesNotRetryPermanentError(t *testing.T) {
	orig := transport.DefaultHttpClient
	origDelay := apiLoginRetryDelay
	defer func() {
		transport.DefaultHttpClient = orig
		apiLoginRetryDelay = origDelay
	}()

	apiLoginRetryDelay = 0
	transport.DefaultHttpClient = &transport.MockHttpClient{
		Responses: []transport.MockHttpResponse{
			{Code: 400, Body: []byte(`{"error":"invalid_request"}`)},
		},
	}

	b := NewBwv()
	start := time.Now()
	_, err := b.ApiLogin(map[string][]byte{
		"BW_CLIENTID":     []byte("id"),
		"BW_CLIENTSECRET": []byte("secret"),
	})

	if err == nil {
		t.Fatal("expected error from permanent 400, got nil (login was retried into a spurious success)")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("ApiLogin took %s - a permanent error should fail fast, not retry", elapsed)
	}
}
