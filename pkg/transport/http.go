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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
)

// AuthToken is a container for the authentication token that is used to
// authenticate with the upstream server.
type AuthToken struct{}

// Post sends a POST request to the given urlstr with the given send body.
// The response is decoded into the given recv object.
//
// If the send object is a url.Values, the request will be sent with
// Content-Type: application/x-www-form-urlencoded.
//
// If the send object is not a url.Values, the request will be sent with
// Content-Type: application/json.
//
// If the send object is a url.Values and the username and scope fields are
// set, the request will be sent with an extra header:
//
//	Auth-Email: <base64-encoded username>
func (c *client) Post(ctx context.Context, urlstr string, recv, send any) error {
	var (
		reader      io.Reader
		contentType string = "application/json"
		authEmail   string = ""
		request     *http.Request
		err         error
		buffer      *bytes.Buffer
	)

	if values, ok := send.(url.Values); ok {
		// Some endpoints only accept urlencoded bodies.
		reader = strings.NewReader(values.Encode())
		contentType = "application/x-www-form-urlencoded"

		if email := values.Get("username"); email != "" && values.Get("scope") != "" {
			authEmail = email
		}
	} else {
		buffer = new(bytes.Buffer)
		if err := json.NewEncoder(buffer).Encode(send); err != nil {
			return err
		}
		reader = buffer
	}
	request, err = http.NewRequest("POST", urlstr, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", contentType)
	if authEmail != "" {
		// For login requests, the upstream bitwarden server wants an extra header.
		// They also require the value to be base64-encoded, for some reason.
		// See: https://github.com/bitwarden/server/blob/6b629feb030e01966189ca1b5339ab85fa5e690c/src/Core/IdentityServer/ResourceOwnerPasswordValidator.cs#L139
		request.Header.Set("Auth-Email", base64.URLEncoding.EncodeToString([]byte(authEmail)))
	}
	return c.DoWithBackoff(ctx, request, recv)
}

// Get sends a GET request to the given urlstr.
// The response is decoded into the given recv object.
func (c *client) Get(ctx context.Context, urlstr string, recv interface{}) error {
	req, err := http.NewRequest("GET", urlstr, nil)
	if err != nil {
		return err
	}
	return c.DoWithBackoff(ctx, req, recv)
}

// DoWithBackoff sends the given request and decodes the response into the given
// recv object. If the request fails, it will retry with exponential backoff.
func (c *client) DoWithBackoff(ctx context.Context, req *http.Request, recv interface{}) error {
	var (
		testInitialInterval     = 500 * time.Millisecond
		testRandomizationFactor = 0.1
		testMultiplier          = 2.0
		testMaxInterval         = 5 * time.Second
		testMaxElapsedTime      = 15 * time.Minute
	)
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = testInitialInterval
	exp.RandomizationFactor = testRandomizationFactor
	exp.Multiplier = testMultiplier
	exp.MaxInterval = testMaxInterval
	exp.MaxElapsedTime = testMaxElapsedTime

	exp.Reset()
	f := func() error {
		return c.Do(ctx, req, recv)
	}

	notify := func(err error, d time.Duration) {
		fmt.Fprintf(os.Stderr, "Retrying in %s after error: %v\n", d, err)
	}

	return backoff.RetryNotifyWithTimer(f, exp, notify, nil)
}

// Do sends the given request and decodes the response into the given recv
// object. If the request fails, it will return an error.
//
// If the request fails with a 400, 401, 403, 404, or 409 status code, the
// error will be a *backoff.PermanentError with the HTTP error wrapped inside
// against the `Err` property.
//
// On success the response body will be JSON decoded into the given recv object.
func (c *client) Do(ctx context.Context, req *http.Request, recv any) error {
	if token, ok := ctx.Value(AuthToken{}).(string); ok {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "curl/8.2.1")

	var (
		response *http.Response
		err      error
		body     []byte
	)
	if response, err = c.Client.Do(req); err != nil {
		return err
	}

	defer response.Body.Close()
	if body, err = io.ReadAll(response.Body); err != nil {
		return err
	}

	switch response.StatusCode {
	case 200:
		break
	case 400:
		return &backoff.PermanentError{
			Err: &ErrBadRequest{response.StatusCode, body},
		}
	case 401:
		return &backoff.PermanentError{
			Err: &ErrUnauthorized{response.StatusCode, body},
		}
	case 403:
		return &backoff.PermanentError{
			Err: &ErrForbidden{response.StatusCode, body},
		}
	case 404:
		return &backoff.PermanentError{
			Err: &ErrNotFound{response.StatusCode, body},
		}
	case 409:
		return &backoff.PermanentError{
			Err: &ErrConflict{response.StatusCode, body},
		}
	case 500:
		return &ErrInternal{response.StatusCode, body}
	default:
		return &ErrUnknown{response.StatusCode, body}

	}

	err = json.Unmarshal(body, recv)
	return err
}
