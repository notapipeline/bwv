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

	"github.com/notapipeline/bwv/pkg/types"
)

type MaliciousTrafficError struct{}

func (e *MaliciousTrafficError) Error() string {
	return "Traffic from your network looks unusual. " +
		"Connect to a different network or try again later."
}

type ErrorModel struct {
	Message string
	Object  string
}

// {"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0"],"TwoFactorProviders2":{"0":null},"MasterPasswordPolicy":null}
// {"error":"invalid_grant","error_description":"invalid_username_or_password","ErrorModel":{"Message":"Two-step token is invalid. Try again.","Object":"error"}}...
type TwoFactorRequiredError struct {
	Err                  string `json:"error"`
	ErrorDescription     string `json:"error_description"`
	ErrorModel           *ErrorModel
	TwoFactorProviders   []string
	TwoFactorProviders2  map[types.TwoFactorProvider]map[string]interface{}
	MasterPasswordPolicy interface{}
}

func (e *TwoFactorRequiredError) Error() string {
	return fmt.Sprintf("%s: %s", e.Err, e.ErrorDescription)
}

// {"message":"Slow down! Too many requests. Try again in 1m.","validationErrors":null,"exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}
type RateLimitError struct{}

func (e *RateLimitError) Error() string {
	return "Slow down! Too many requests. Try again in 1m."
}

type ErrInvalidStatusCode struct {
	Code int
}

func (e *ErrInvalidStatusCode) Error() string {
	return fmt.Sprintf("Invalid status code %d", e.Code)
}

type ErrBase struct {
	Code int
	Body []byte
}

type ErrStatusCode ErrBase

func (e *ErrStatusCode) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrBadRequest ErrBase

func (e *ErrBadRequest) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrUnauthorized ErrBase

func (e *ErrUnauthorized) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrForbidden ErrBase

func (e *ErrForbidden) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrNotFound ErrBase

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrConflict ErrBase

func (e *ErrConflict) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrTooManyRequests ErrBase

func (e *ErrTooManyRequests) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrInternal ErrBase

func (e *ErrInternal) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}

type ErrUnknown ErrBase

func (e *ErrUnknown) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.Code), e.Body)
}
