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

type AuthToken struct{}

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

func (c *client) Get(ctx context.Context, urlstr string, recv interface{}) error {
	req, err := http.NewRequest("GET", urlstr, nil)
	if err != nil {
		return err
	}
	return c.DoWithBackoff(ctx, req, recv)
}

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

func (c *client) Do(ctx context.Context, req *http.Request, recv any) error {
	if token, ok := ctx.Value(AuthToken{}).(string); ok {
		req.Header.Set("Authorization", "Bearer "+token)
	}

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

	if response.StatusCode != 200 {
		return &ErrStatusCode{response.StatusCode, body}
	}

	err = json.Unmarshal(body, recv)

	return err
}
