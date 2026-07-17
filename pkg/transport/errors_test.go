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
	"testing"
)

func TestIsPermanent(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"bad request", &ErrBadRequest{Code: 400}, true},
		{"unauthorized", &ErrUnauthorized{Code: 401}, true},
		{"forbidden", &ErrForbidden{Code: 403}, true},
		{"not found", &ErrNotFound{Code: 404}, true},
		{"conflict", &ErrConflict{Code: 409}, true},
		{"wrapped bad request", fmt.Errorf("login failed: %w", &ErrBadRequest{Code: 400}), true},
		{"too many requests", &ErrTooManyRequests{Code: 429}, false},
		{"internal", &ErrInternal{Code: 500}, false},
		{"network error", fmt.Errorf("connection refused"), false},
		{"nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermanent(tt.err); got != tt.want {
				t.Errorf("IsPermanent(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
