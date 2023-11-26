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

type ErrInvalidStatusCode struct {
	Code int
}

func (e *ErrInvalidStatusCode) Error() string {
	return fmt.Sprintf("Invalid status code %d", e.Code)
}

type ErrBadRequest struct {
	Code int
	Body []byte
}

func (e *ErrBadRequest) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrUnauthorized struct {
	Code int
	Body []byte
}

func (e *ErrUnauthorized) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrForbidden struct {
	Code int
	Body []byte
}

func (e *ErrForbidden) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrNotFound struct {
	Code int
	Body []byte
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrConflict struct {
	Code int
	Body []byte
}

func (e *ErrConflict) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrInternal struct {
	Code int
	Body []byte
}

func (e *ErrInternal) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrUnknown struct {
	Code int
	Body []byte
}

func (e *ErrUnknown) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}
