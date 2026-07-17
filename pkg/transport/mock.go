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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"

	backoff "github.com/cenkalti/backoff/v4"
	"github.com/notapipeline/bwv/pkg/types"
)

type MockHttpResponse struct {
	Code int
	Body []byte
}

// MockHttpClient is a mock implementation of the HttpClient interface
// Useful for testing requests throughout the application
type MockHttpClient struct {
	Responses []MockHttpResponse

	// LastPostURL and LastPostBody record the most recent Post so tests can
	// assert the endpoint and payload actually sent (the mock returns queued
	// responses regardless, so without this a wrong URL/body goes unnoticed).
	LastPostURL  string
	LastPostBody any
}

func (m *MockHttpClient) Get(ctx context.Context, urlstr string, recv any) error {
	return m.DoWithBackoff(ctx, nil, recv)
}

func (m *MockHttpClient) Post(ctx context.Context, urlstr string, recv, send any) error {
	m.LastPostURL = urlstr
	m.LastPostBody = send
	return m.DoWithBackoff(ctx, nil, recv)
}

func (m *MockHttpClient) DoWithBackoff(ctx context.Context, req *http.Request, response any) error {
	return m.Do(ctx, req, response)
}

func (m *MockHttpClient) Do(ctx context.Context, req *http.Request, recv any) error {
	if len(m.Responses) == 0 {
		return nil
	}
	response := m.Responses[0]
	m.Responses = m.Responses[1:]
	switch response.Code {
	// Hard errors. cannot be retried - mirror the concrete types the real
	// client returns so transport.IsPermanent classifies them correctly.
	case 400:
		return &ErrBadRequest{Code: response.Code, Body: []byte(response.Body)}
	case 401:
		return &ErrUnauthorized{Code: response.Code, Body: []byte(response.Body)}
	case 403:
		return &ErrForbidden{Code: response.Code, Body: []byte(response.Body)}
	case 404:
		return &ErrNotFound{Code: response.Code, Body: []byte(response.Body)}
	case 409:
		return &ErrConflict{Code: response.Code, Body: []byte(response.Body)}
	// Soft errors. can be retried
	case 429, 500, 502, 503, 504:
		return m.Do(ctx, req, recv)
	}

	var err error
	if err = json.Unmarshal(response.Body, recv); err != nil {
		// JSON can't decode attachments as they aren't in JSON format.
		// therefore we're normally passing in a SecretResponse object.
		if secretResponse, ok := recv.(*types.SecretResponse); ok {
			secretResponse.Message = base64.StdEncoding.EncodeToString(response.Body)
			return nil
		}

		// for anything else, return the error
		err = &backoff.PermanentError{Err: &json.UnmarshalTypeError{
			Value: "body", Type: reflect.TypeOf(recv)},
		}
	}

	return err
}
