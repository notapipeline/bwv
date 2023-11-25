package transport

import (
	"context"
	"net/http"
	"time"
)

type HttpClient interface {
	Post(ctx context.Context, urlstr string, recv, send interface{}) error
	Get(ctx context.Context, urlstr string, recv interface{}) error
	DoWithBackoff(ctx context.Context, req *http.Request, recv interface{}) error
}

type client struct {
	*http.Client
}

var c client = client{
	&http.Client{
		Timeout: 10 * time.Second,
	},
}

var DefaultHttpClient HttpClient = &c
