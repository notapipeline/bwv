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
package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/notapipeline/bwv/pkg/types"
	"golang.org/x/crypto/pbkdf2"
)

func TestDeriveMasterKeyPBKDF2(t *testing.T) {
	password := []byte("password")
	email := "test@example.com"
	kdf := types.KDFInfo{
		Type:       types.KDFTypePBKDF2,
		Iterations: 1000,
	}

	var expected string = "ZRutCjCltjwPo2il9HazrIn9+4t0r+5BI0lVv+Wktr0="

	key, err := DeriveMasterKey(password, email, kdf)
	var k string = base64.StdEncoding.EncodeToString(key)
	if err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	if len(k) != len(expected) {
		t.Errorf("Expected key length %d but got %d", len(expected), len(key))
	}

	if k != expected {
		t.Errorf("Expected key byte %q but got %q", expected, k)
	}
}

func TestDeriveMasterKeyArgon2id(t *testing.T) {
	password := []byte("password")
	email := "test@example.com"
	kdf := types.KDFInfo{
		Type:        types.KDFTypeArgon2id,
		Iterations:  1000,
		Memory:      types.IntPtr(64),
		Parallelism: types.IntPtr(4),
	}
	var expected string = "DKlUxailv+s41uCt/R1NKxvQ9wOjsDOYdBpaOxC9vV4="

	key, err := DeriveMasterKey(password, email, kdf)
	var k string = base64.StdEncoding.EncodeToString(key)

	if err != nil {
		t.Errorf("Expected nil error but got %v", err)
	}

	if len(k) != len(expected) {
		t.Errorf("Expected key length %d but got %d", len(expected), len(key))
	}

	if k != expected {
		t.Errorf("Expected key byte %q but got %q", expected, k)
	}
}

func TestDeriveMasterKeyUnsupportedKDF(t *testing.T) {
	password := []byte("password")
	email := "test@example.com"
	kdf := types.KDFInfo{
		Type:       999, // unsupported KDF type
		Iterations: 1000,
	}

	key, err := DeriveMasterKey(password, email, kdf)
	if key != nil {
		t.Errorf("Expected nil key but got %v", key)
	}

	expectedError := fmt.Sprintf("unsupported KDF type %d", kdf.Type)
	if err == nil {
		t.Errorf("Expected error but got nil")
	} else if err.Error() != expectedError {
		t.Errorf("Expected error message %q but got %q", expectedError, err.Error())
	}
}
func TestEncryptWith(t *testing.T) {

	var (
		data     []byte = []byte("hello world")
		value    []byte
		cs       types.CipherString
		exp      string = "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4="
		mpw      []byte = pbkdf2.Key([]byte("masterpw"), []byte("email@example.com"), 800000, 32, sha256.New)
		key, mac []byte
		err      error
	)
	_ = cs.UnmarshalText([]byte(exp))

	if key, mac, err = StretchKey(mpw); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	cipherString, err := EncryptWith(data, types.AesCbc256_HmacSha256_B64, key, mac)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	value, err = DecryptWith(cipherString, key, mac)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if string(value) != string(data) {
		t.Fatalf("Expected %q but got %q", string(data), string(value))
	}
}

func TestEncryptReturnsErrorOnInvalidType(t *testing.T) {
	var err error
	_, err = EncryptWith([]byte("test"), types.CipherStringType(999), []byte("key"), []byte("mac"))
	if err == nil {
		t.Fatalf("Expected nil error: %v", err)
	}
}

func TestEncrptWithReturnsErrorIfNoMac(t *testing.T) {
	var (
		data []byte = []byte("hello world")
		cs   types.CipherString
		exp  string = "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4="
		mpw  []byte = pbkdf2.Key([]byte("masterpw"), []byte("email@example.com"), 800000, 32, sha256.New)
		key  []byte
		err  error
	)
	_ = cs.UnmarshalText([]byte(exp))

	if key, _, err = StretchKey(mpw); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = EncryptWith(data, types.AesCbc256_HmacSha256_B64, key, nil)
	if err == nil {
		t.Fatalf("Expected error but got nil")
	}

	if err != nil && err.Error() != "encrypt: cipher string type expects a MAC" {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestDecryptWithUnsupportedCipherType(t *testing.T) {
	var (
		cs       types.CipherString
		exp      string = "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4="
		mpw      []byte = pbkdf2.Key([]byte("masterpw"), []byte("email@example.com"), 800000, 32, sha256.New)
		key, mac []byte
		err      error
	)
	if err = cs.UnmarshalText([]byte(exp)); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	cs.Type = types.CipherStringType(999) // unsupported cipher type

	if key, mac, err = StretchKey(mpw); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = DecryptWith(cs, key, mac)
	if err == nil {
		t.Errorf("Expected error but got nil")
	}

	expectedError := fmt.Sprintf("decrypt: unsupported cipher type %q", cs.Type)
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error message %q but got %q", expectedError, err.Error())
	}
}

func TestDecryptWithMissingMAC(t *testing.T) {
	var (
		cs       types.CipherString
		exp      string = "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4="
		mpw      []byte = pbkdf2.Key([]byte("masterpw"), []byte("email@example.com"), 800000, 32, sha256.New)
		key, mac []byte
		err      error
	)
	if err = cs.UnmarshalText([]byte(exp)); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	cs.MAC = []byte{}

	if key, mac, err = StretchKey(mpw); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err = DecryptWith(cs, key, mac); err == nil {
		t.Errorf("Expected error but got nil")
	}

	expectedError := "decrypt: cipher string type expects a MAC"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error message %q but got %q", expectedError, err.Error())
	}
}

func TestDecryptWithInvalidMAC(t *testing.T) {
	var (
		cs       types.CipherString
		exp      string = "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4="
		mpw      []byte = pbkdf2.Key([]byte("masterpw"), []byte("email@example.com"), 800000, 32, sha256.New)
		key, mac []byte
		err      error
	)
	if err = cs.UnmarshalText([]byte(exp)); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	cs.MAC = []byte{1, 2, 3, 4, 5, 6}

	if key, mac, err = StretchKey(mpw); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err = DecryptWith(cs, key, mac); err == nil {
		t.Errorf("Expected error but got nil")
	}

	expectedError := "decrypt: MAC mismatch"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error message %q but got %q", expectedError, err.Error())
	}
}
func TestPadPKCS7(t *testing.T) {
	testCases := []struct {
		test     string
		src      []byte
		size     int
		expected []byte
	}{
		{
			test:     "hello padded to 8 bytes",
			src:      []byte("hello"),
			size:     8,
			expected: []byte("hello\x03\x03\x03"),
		},
		{
			test:     "world padded to 16 bytes",
			src:      []byte("world"),
			size:     16,
			expected: []byte("world\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		},
		{
			test:     "tes padded to 4 bytes",
			src:      []byte("tes"),
			size:     4,
			expected: []byte("tes\x01"),
		},
	}

	for _, tc := range testCases {
		t.Log(tc.test)
		padded, err := PadPKCS7(tc.src, tc.size)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !bytes.Equal(padded, tc.expected) {
			t.Errorf("Expected %v but got %v", tc.expected, padded)
		}
	}
}

func TestUnpad(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		expectedOutput []byte
		shouldErr      bool
	}{
		{
			name:           "base case",
			input:          []byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
			expectedOutput: []byte("YELLOW SUBMARINE"),
			shouldErr:      false,
		}, {
			name:           "too few pad bytes",
			input:          []byte("YELLOW SUBMARINE\x04\x04\x04"),
			expectedOutput: nil,
			shouldErr:      true,
		}, {
			name:           "unmatching pad bytes",
			input:          []byte("YELLOW SUBMARINE\x01\x02\x03\x04\x05"),
			expectedOutput: nil,
			shouldErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := UnpadPKCS7(test.input, 4)
			if test.shouldErr {
				if err == nil {
					t.Error("expected: error, got: nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected: nil error, got: %s", err)
				}
			}

			if !bytes.Equal(res, test.expectedOutput) {
				t.Errorf("expected: %s, got %s", test.expectedOutput, res)
			}
		})
	}
}
