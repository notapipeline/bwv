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
package transport

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"
)

type HttpClient interface {
	Post(ctx context.Context, urlstr string, recv, send any) error
	Get(ctx context.Context, urlstr string, recv any) error
	DoWithBackoff(ctx context.Context, req *http.Request, recv any) error
}

type client struct {
	*http.Client

	// maxElapsed bounds how long DoWithBackoff keeps retrying. Zero or less
	// attempts the request exactly once.
	maxElapsed time.Duration
}

var c client = client{
	Client: &http.Client{
		Timeout: 10 * time.Second,
	},
	maxElapsed: 15 * time.Minute,
}

var DefaultHttpClient HttpClient = &c

// NewHttpClient returns an HttpClient with its own TLS settings and retry
// budget, for callers that cannot use the shared one. A maxElapsed of zero
// attempts each request exactly once: the shared client's 15 minute budget
// suits the Bitwarden API, but it is far too long to make an embedding
// application wait on a local daemon that is not listening.
func NewHttpClient(tlsConfig *tls.Config, timeout, maxElapsed time.Duration) HttpClient {
	return &client{
		Client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		maxElapsed: maxElapsed,
	}
}
