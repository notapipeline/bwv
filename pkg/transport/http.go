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
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	"github.com/notapipeline/bwv/pkg/types"
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

	if request, err = http.NewRequest("POST", urlstr, reader); err != nil {
		return err
	}

	// We need to set the GetBody function here so that the request can be
	// retried. If we don't set this, the request will fail on retry with
	// 400 Bad Request as the body has already been read
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(reader), nil
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
//
// This is a wrapper to `DoWithBackoff` so the request is retried on failure.
func (c *client) Get(ctx context.Context, urlstr string, recv any) error {
	req, err := http.NewRequest("GET", urlstr, nil)
	if err != nil {
		return err
	}
	return c.DoWithBackoff(ctx, req, recv)
}

// DoWithBackoff applies a reqest retry policy to the given request
//
// By default, this will retry the request up to a max interval of 15 minutes.
// using a jitter with a max of 500 miliseconds.
//
// If the request is >= 400 and < 429, the request will be retried but instead
// cancelled and the underlying error will instead be returned.
func (c *client) DoWithBackoff(ctx context.Context, req *http.Request, recv any) error {
	var (
		initialInterval     = 500 * time.Millisecond
		randomizationFactor = 0.1
		multiplier          = 2.0
		maxInterval         = 5 * time.Second
		maxElapsedTime      = 15 * time.Minute
	)
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = initialInterval
	exp.RandomizationFactor = randomizationFactor
	exp.Multiplier = multiplier
	exp.MaxInterval = maxInterval
	exp.MaxElapsedTime = maxElapsedTime

	exp.Reset()
	f := func() error {
		return c.Do(ctx, req, recv)
	}

	notify := func(err error, d time.Duration) {
		log.Printf("Retrying in %s after error: %v", d, err)
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
	req.Header.Set("User-Agent", "bwv/0.0.1")

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
	case http.StatusOK:
		break
	case http.StatusBadRequest:
		if bytes.Contains(body, []byte("TwoFactor")) || bytes.Contains(body, []byte("Two-step")) {
			var tfa TwoFactorRequiredError
			if err = json.Unmarshal(body, &tfa); err == nil {
				return &backoff.PermanentError{
					Err: &tfa,
				}
			}
		}

		return &backoff.PermanentError{
			Err: &ErrBadRequest{response.StatusCode, body},
		}
	case http.StatusUnauthorized:
		return &backoff.PermanentError{
			Err: &ErrUnauthorized{response.StatusCode, body},
		}
	case http.StatusForbidden:
		return &backoff.PermanentError{
			Err: &ErrForbidden{response.StatusCode, body},
		}
	case http.StatusNotFound:
		return &backoff.PermanentError{
			Err: &ErrNotFound{response.StatusCode, body},
		}
	case http.StatusConflict:
		return &backoff.PermanentError{
			Err: &ErrConflict{response.StatusCode, body},
		}
	case http.StatusTooManyRequests:
		return &ErrTooManyRequests{response.StatusCode, body}
	case http.StatusInternalServerError:
		return &ErrInternal{response.StatusCode, body}
	default:
		return &ErrUnknown{response.StatusCode, body}

	}

	if err = json.Unmarshal(body, recv); err != nil {
		// JSON can't decode attachments as they aren't in JSON format.
		// therefore we're normally passing in a SecretResponse object.
		if secretResponse, ok := recv.(*types.SecretResponse); ok {
			secretResponse.Message = base64.StdEncoding.EncodeToString(body)
			recv = secretResponse //nolint:golint,ineffassign
			return nil
		}

		// for anything else, return the error
		err = &backoff.PermanentError{Err: &json.UnmarshalTypeError{
			Value: "body", Type: reflect.TypeOf(recv)},
		}
	}
	return err
}
