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
	"encoding/json"
	"net/http"
)

type MockHttpResponse struct {
	Code int
	Body string
}

// MockHttpClient is a mock implementation of the HttpClient interface
// Useful for testing requests throughout the application
type MockHttpClient struct {
	Responses []MockHttpResponse
}

func (m *MockHttpClient) Get(ctx context.Context, urlstr string, recv interface{}) error {
	return m.DoWithBackoff(context.Background(), nil, recv)
}

func (m *MockHttpClient) Post(ctx context.Context, urlstr string, recv, send any) error {
	return m.DoWithBackoff(context.Background(), nil, recv)
}

func (m *MockHttpClient) DoWithBackoff(ctx context.Context, req *http.Request, response interface{}) error {
	return m.Do(context.Background(), req, response)
}

func (m *MockHttpClient) Do(ctx context.Context, req *http.Request, recv any) error {
	if len(m.Responses) == 0 {
		return nil
	}
	response := m.Responses[0]
	m.Responses = m.Responses[1:]
	switch response.Code {
	// Hard errors. cannot be retried
	case 400, 401, 403, 404:
		return &ErrUnknown{
			Code: response.Code,
			Body: []byte(response.Body),
		}
	// Soft errors. can be retried
	case 429, 500, 502, 503, 504:
		return m.Do(ctx, req, recv)
	}
	err := json.Unmarshal([]byte(response.Body), recv)
	return err
}
