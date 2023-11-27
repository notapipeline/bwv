package cmd

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/notapipeline/bwv/pkg/transport"
)

// MockHttpClient is a mock implementation of the HttpClient interface
// Useful for testing requests throughout the application
type MockHttpClient struct {
	responses []struct {
		code int
		body string
	}
}

func (m *MockHttpClient) DoWithBackoff(ctx context.Context, req *http.Request, response interface{}) error {
	return m.Do(context.Background(), req, response)
}

func (m *MockHttpClient) Do(ctx context.Context, req *http.Request, recv any) error {
	if len(m.responses) == 0 {
		return nil
	}
	response := m.responses[0]
	m.responses = m.responses[1:]
	switch response.code {
	case 400, 401, 403, 404, 429, 500, 503:
		return &transport.ErrUnknown{
			Code: response.code,
			Body: []byte(response.body),
		}
	}
	if err := json.Unmarshal([]byte(response.body), recv); err != nil {
		r := recv.(*struct {
			Code    int    `json:"statuscode"`
			Message string `json:"message"`
		})
		r.Code = response.code
		r.Message = response.body
	}
	return nil

}

func (m *MockHttpClient) Get(ctx context.Context, urlstr string, recv interface{}) error {
	return m.DoWithBackoff(context.Background(), nil, recv)
}

func (m *MockHttpClient) Post(ctx context.Context, urlstr string, recv, send any) error {
	return m.DoWithBackoff(context.Background(), nil, recv)
}

type MockProcess struct {
	value                                   string
	status                                  bool
	readlnerr, closeerr, starterr, writeerr error
	exit                                    int
	lines                                   []struct {
		line []byte
		err  error
	}
}

func (m *MockProcess) ReadLine() ([]byte, bool, error) {
	line := m.lines[0]
	m.lines = m.lines[1:]
	return line.line, m.status, line.err
}

func (m *MockProcess) Start(string, []string) error {
	return m.starterr
}

func (m *MockProcess) Close() error {
	return m.closeerr
}

func (m *MockProcess) Write([]byte) (int, error) {
	return m.exit, m.writeerr
}
