package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"testing"

	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/twpayne/go-pinentry"
)

type MockClient struct {
	code int
	body string
}

func (m *MockClient) DoWithBackoff(ctx context.Context, req *http.Request, response interface{}) error {
	return m.Do(context.Background(), req, response)
}

func (m *MockClient) Do(ctx context.Context, req *http.Request, recv any) error {
	r := recv.(*struct {
		Code    int    `json:"statuscode"`
		Message string `json:"message"`
	})
	r.Code = m.code
	r.Message = m.body
	return nil

}

func (m *MockClient) Get(ctx context.Context, urlstr string, recv interface{}) error {
	return m.DoWithBackoff(context.Background(), nil, recv)
}

func (m *MockClient) Post(ctx context.Context, urlstr string, recv, send any) error {
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

func TestGenkeyCmd(t *testing.T) {
	tests := []struct {
		name        string
		addresses   []string
		email       string
		expectedErr error
		status      *struct {
			code int
			body string
		}
	}{
		{
			name: "no addresses",
			addresses: []string{
				"localhost",
			},
			email:       "test@example.com",
			expectedErr: nil,
			status: &struct {
				code int
				body string
			}{code: 200, body: `{"message":"stored token for address localhost"}`},
		},
		{
			name:        "no email",
			addresses:   []string{"localhost"},
			email:       "",
			expectedErr: errors.New("invalid email address \"mail: no address\""),
			status: &struct {
				code int
				body string
			}{code: 0, body: ""},
		},
		{
			name:        "rate limited",
			addresses:   []string{"localhost"},
			email:       "test@example.com",
			expectedErr: errors.New(`Failed to store token: {"message":"Traffic from your network looks unusual. Connect to a different network or try again later. [Error Code 6]"}`),
			status: &struct {
				code int
				body string
			}{
				code: 400,
				body: `{"message":"Traffic from your network looks unusual. Connect to a different network or try again later. [Error Code 6]"}`,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Mock getPassword function
			opwd := getPassword
			defer func() {
				getPassword = opwd
			}()
			getPassword = func() (string, error) {
				return "password", nil
			}
			email = test.email

			// Mock transport.DefaultHttpClient.DoWithBackoff function
			transport.DefaultHttpClient = &MockClient{
				code: test.status.code,
				body: test.status.body,
			}
			// Capture log output
			var buf bytes.Buffer
			log.SetOutput(&buf)
			of := fatal
			defer func() {
				fatal = of
				log.SetFlags(log.Flags() & (log.Ldate | log.Ltime))
			}()
			fatal = func(format string, v ...interface{}) {
				log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
				log.Printf(format, v...)
			}

			genkeyCmd.Run(genkeyCmd, test.addresses)

			t.Log(buf.String())
			if test.expectedErr != nil {
				if buf.String() != test.expectedErr.Error()+"\n" {
					t.Errorf("Expected log output %q, but got %q", test.expectedErr.Error()+"\n", buf.String())
				}
				return
			}

			var re = regexp.MustCompile(`(?m).*\t[a-zA-Z0-9]{32}`)
			matches := re.FindAllString(buf.String(), -1)
			if len(matches) != len(test.addresses) {
				t.Errorf("Expected %d tokens, but got %d", len(test.addresses), len(matches))
			}
		})
	}
}
func TestGetPassword(t *testing.T) {
	tests := []struct {
		name             string
		expectedResult   string
		expectedErr      error
		mockClient       func(options ...pinentry.ClientOption) (c *pinentry.Client, err error)
		mockReadPassword func(prompt string) (password string, err error)
	}{
		{
			name:           "cancelled context",
			expectedResult: "",
			expectedErr:    fmt.Errorf("Cancelled"),
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				process := MockProcess{
					value:  "",
					status: true,
					readlnerr: &pinentry.AssuanError{
						Code: pinentry.AssuanErrorCodeCancelled,
					},
					lines: []struct {
						line []byte
						err  error
					}{
						{line: []byte("OK"), err: nil},
						{line: []byte{}, err: &pinentry.AssuanError{Code: pinentry.AssuanErrorCodeCancelled}},
						{line: []byte("BYE"), err: nil},
					},
				}
				return pinentry.NewClient(pinentry.WithProcess(&process))
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", nil
			},
		},
		{
			name:           "no pinentry binary",
			expectedResult: "",
			expectedErr:    fmt.Errorf("liner: function not supported in this terminal"),
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				return nil, fmt.Errorf("exec: \"pinentry\": executable file not found in $PATH")
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", errors.New("liner: function not supported in this terminal")
			},
		},
		{
			name:           "liner: no password provided",
			expectedResult: "",
			expectedErr:    fmt.Errorf("No password provided"),
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				return nil, fmt.Errorf("exec: \"pinentry\": executable file not found in $PATH")
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", nil
			},
		},
		{
			name:           "success",
			expectedResult: "password",
			expectedErr:    nil,
			mockClient: func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
				process := MockProcess{
					value:  "password",
					status: true,
					lines: []struct {
						line []byte
						err  error
					}{
						{line: []byte("OK"), err: nil},
						{line: []byte("D password"), err: nil},
						{line: []byte("OK"), err: nil},
						{line: []byte("BYE"), err: nil},
					},
				}
				return pinentry.NewClient(pinentry.WithProcess(&process))
			},
			mockReadPassword: func(prompt string) (password string, err error) {
				return "", nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ope := getPinentry
			orp := readPassword
			defer func() {
				getPinentry = ope
				readPassword = orp
			}()
			getPinentry = test.mockClient
			readPassword = test.mockReadPassword
			actualResult, actualErr := getPassword()

			if actualResult != test.expectedResult {
				t.Errorf("Expected password %q, but got %q", test.expectedResult, actualResult)
			}

			if test.expectedErr != nil {
				if actualErr.Error() != test.expectedErr.Error() {
					t.Errorf("Expected error %v, but got %v", test.expectedErr, actualErr)
				}
			}
		})
	}
}
