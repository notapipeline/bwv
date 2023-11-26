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
package types

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCipherString_UnmarshalText(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected error
		message  string
	}{
		{
			name:     "Empty input",
			input:    []byte{},
			expected: nil,
		},
		{
			name:     "Invalid cipher string given gibberish",
			input:    []byte("gibberish"),
			expected: MissingTypeError{},
			message:  "cipher string does not contain a type: gibberish",
		},
		{
			name:     "Invalid cipher string type",
			input:    []byte("invalid_type.abc|def|ghi"),
			expected: InvalidTypeError{},
			message:  "invalid cipher string type: invalid_type",
		},
		{
			name:     "Unsupported cipher string type",
			input:    []byte("4.abc|def|ghi"),
			expected: UnsupportedTypeError{},
			message:  "unsupported cipher string type: 4",
		},
		{
			name:     "Invalid number of parts",
			input:    []byte("1.abc"),
			expected: fmt.Errorf("invalid cipher string: expected 2 or 3 parts, got 1"),
			message:  "invalid cipher string: expected 2 or 3 parts, got 1",
		},
		{
			name:     "Invalid IV",
			input:    []byte("1.abc|def|ghi"),
			expected: fmt.Errorf("invalid IV: illegal base64 data at input byte 0"),
			message:  "invalid IV: illegal base64 data at input byte 0",
		},
		{
			name:     "Invalid CT",
			input:    []byte("1.aGVsbG8gd29ybGQK|def|ghi"),
			expected: fmt.Errorf("invalid CT: illegal base64 data at input byte 0"),
			message:  "invalid CT: illegal base64 data at input byte 0",
		},
		{
			name:     "Invalid MAC",
			input:    []byte("1.aGVsbG8gd29ybGQK|Z29vZGJ5ZSBjcnVlbCB3b3JsZAo=|ghi"),
			expected: fmt.Errorf("invalid MAC: illegal base64 data at input byte 0"),
			message:  "invalid MAC: illegal base64 data at input byte 0",
		},
		{
			name:     "Valid cipher string without MAC",
			input:    []byte("0.aGVsbG8gd29ybGQK|Z29vZGJ5ZSBjcnVlbCB3b3JsZAo="),
			expected: nil,
		},
		{
			name:     "Valid cipher string with MAC",
			input:    []byte("1.aGVsbG8gd29ybGQK|Z29vZGJ5ZSBjcnVlbCB3b3JsZAo=|eW91J3JlIHdlbGNvbWUK"),
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cs := &CipherString{}
			err := cs.UnmarshalText(test.input)
			if err != nil && errors.Is(err, test.expected) {
				assert.Equal(t, err.Error(), test.message)
				t.Errorf("Expected error '%v' but got '%v'", test.expected, err)
			}
		})
	}
}
func TestCipherString_String(t *testing.T) {
	tests := []struct {
		name     string
		input    CipherString
		expected string
	}{
		{
			name:     "Empty CipherString",
			input:    CipherString{},
			expected: "",
		},
		{
			name: "CipherString without MAC",
			input: CipherString{
				Type: CipherStringType(0),
				IV:   []byte("hello world"),
				CT:   []byte("goodbye cruel world"),
			},
			expected: "0.aGVsbG8gd29ybGQ=|Z29vZGJ5ZSBjcnVlbCB3b3JsZA==",
		},
		{
			name: "CipherString with MAC",
			input: CipherString{
				Type: CipherStringType(1),
				IV:   []byte("hello world"),
				CT:   []byte("goodbye cruel world"),
				MAC:  []byte("you're welcome"),
			},
			expected: "1.aGVsbG8gd29ybGQ=|Z29vZGJ5ZSBjcnVlbCB3b3JsZA==|eW91J3JlIHdlbGNvbWU=",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.input.String()
			if result != test.expected {
				t.Errorf("Expected '%s' but got '%s'", test.expected, result)
			}
		})
	}
}
func TestCipherString_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		input    CipherString
		expected []byte
	}{
		{
			name:     "Empty CipherString",
			input:    CipherString{},
			expected: []byte(""),
		},
		{
			name: "CipherString without MAC",
			input: CipherString{
				Type: CipherStringType(0),
				IV:   []byte("hello world"),
				CT:   []byte("goodbye cruel world"),
			},
			expected: []byte("0.aGVsbG8gd29ybGQ=|Z29vZGJ5ZSBjcnVlbCB3b3JsZA=="),
		},
		{
			name: "CipherString with MAC",
			input: CipherString{
				Type: CipherStringType(1),
				IV:   []byte("hello world"),
				CT:   []byte("goodbye cruel world"),
				MAC:  []byte("you're welcome"),
			},
			expected: []byte("1.aGVsbG8gd29ybGQ=|Z29vZGJ5ZSBjcnVlbCB3b3JsZA==|eW91J3JlIHdlbGNvbWU="),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.input.MarshalText()
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !bytes.Equal(result, test.expected) {
				t.Errorf("Expected '%s' but got '%s'", test.expected, result)
			}
		})
	}
}
