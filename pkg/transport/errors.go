package transport

import (
	"fmt"
	"net/http"
)

type MaliciousTrafficError struct{}

func (e *MaliciousTrafficError) Error() string {
	return "Traffic from your network looks unusual. " +
		"Connect to a different network or try again later."
}

// {"message":"Slow down! Too many requests. Try again in 1m.","validationErrors":null,"exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}
type RateLimitError struct{}

func (e *RateLimitError) Error() string {
	return "Slow down! Too many requests. Try again in 1m."
}

type ErrStatusCode struct {
	Code int
	Body []byte
}

func (e *ErrStatusCode) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}
