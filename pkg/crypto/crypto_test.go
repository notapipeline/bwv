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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"testing"

	"github.com/notapipeline/bwv/pkg/types"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type mockReader struct{}

func (m mockReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("mock reader error")
}

func Teardown(t *testing.T) {
	pbkdfKey = pbkdf2.Key
	argon2ID = argon2.IDKey
	hkdfExpand = hkdf.Expand
	unmarshal = func(cs types.CipherString, text []byte) (types.CipherString, error) {
		err := cs.UnmarshalText(text)
		return cs, err
	}
	newAesCipher = aes.NewCipher
}

func setupSuite(t *testing.T) func(t *testing.T) {
	return Teardown
}

func setMocks(mocks *CryptoMock) {
	if mocks != nil {
		if mocks.PbkdfKey != nil {
			pbkdfKey = mocks.PbkdfKey
		}
		if mocks.Argon2ID != nil {
			argon2ID = mocks.Argon2ID
		}
		if mocks.HkdfExpand != nil {
			hkdfExpand = mocks.HkdfExpand
		}

		if mocks.Unmarshal != nil {
			unmarshal = mocks.Unmarshal
		}
		if mocks.NewAesCipher != nil {
			newAesCipher = mocks.NewAesCipher
		}
	}
}

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		email         string
		kdf           types.KDFInfo
		expected      string
		mocks         *CryptoMock
		expectedError error
	}{
		{
			name:     "base case",
			password: "password",
			email:    "email@example.com",
			kdf: types.KDFInfo{
				Type:        types.KDFTypePBKDF2,
				Iterations:  1000,
				Memory:      nil,
				Parallelism: nil,
			},
			expected:      "hello world",
			expectedError: nil,
		},
		{
			name:     "base case with argon2id",
			password: "password",
			email:    "email@example.com",
			kdf: types.KDFInfo{
				Type:        types.KDFTypeArgon2id,
				Iterations:  10,
				Memory:      types.IntPtr(64),
				Parallelism: types.IntPtr(4),
			},
			expected:      "hello world",
			expectedError: nil,
		},
		{
			name:     "stretch key returns error",
			password: "password",
			email:    "email@example.com",
			kdf: types.KDFInfo{
				Type:        types.KDFTypeArgon2id,
				Iterations:  10,
				Memory:      types.IntPtr(64),
				Parallelism: types.IntPtr(4),
			},
			expected:      "hello world",
			expectedError: fmt.Errorf("unable to stretch master password: mock reader error"),
			mocks: &CryptoMock{
				HkdfExpand: func(hash func() hash.Hash, pseudorandomKey []byte, info []byte) io.Reader {
					return mockReader{}
				},
			},
		},
		{
			name: "pbkdf2.Key returns error",
			kdf: types.KDFInfo{
				Type:        types.KDFTypePBKDF2,
				Iterations:  1000,
				Memory:      nil,
				Parallelism: nil,
			},
			expected:      "hello world",
			expectedError: fmt.Errorf("unable to stretch master password: unable to derive master key"),
			mocks: &CryptoMock{
				PbkdfKey: func(password []byte, salt []byte, iter int, keyLen int, hashFunc func() hash.Hash) []byte {
					return nil
				},
			},
		},
		{
			name: "argon2.IDKey returns error",
			kdf: types.KDFInfo{
				Type:        types.KDFTypeArgon2id,
				Iterations:  10,
				Memory:      types.IntPtr(64),
				Parallelism: types.IntPtr(4),
			},
			expected:      "hello world",
			expectedError: fmt.Errorf("unable to stretch master password: unable to derive master key"),
			mocks: &CryptoMock{
				Argon2ID: func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
					return nil
				},
			},
		},
		{
			name: "unmarshal returns error",
			kdf: types.KDFInfo{
				Type:        types.KDFTypeArgon2id,
				Iterations:  10,
				Memory:      types.IntPtr(64),
				Parallelism: types.IntPtr(4),
			},
			expected:      "hello world",
			expectedError: fmt.Errorf("unable to unmarshal cipher string: cipher string unmarshal error"),
			mocks: &CryptoMock{
				Unmarshal: func(cs types.CipherString, text []byte) (types.CipherString, error) {
					return cs, fmt.Errorf("cipher string unmarshal error")
				},
			},
		},
		{
			name: "newAesCipher returns error",
			kdf: types.KDFInfo{
				Type:        types.KDFTypeArgon2id,
				Iterations:  10,
				Memory:      types.IntPtr(64),
				Parallelism: types.IntPtr(4),
			},
			expected:      "hello world",
			expectedError: fmt.Errorf("unable to encrypt cipher string: unable to create new aes cipher"),
			mocks: &CryptoMock{
				NewAesCipher: func(key []byte) (cipher.Block, error) {
					return nil, fmt.Errorf("unable to create new aes cipher")
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)
			setMocks(test.mocks)

			encrypted, err := ClientEncrypt(test.password, test.email, "hello world", test.kdf)
			if err != nil {
				if err.Error() != test.expectedError.Error() {
					t.Errorf("Expected error %q but got %q", test.expectedError.Error(), err.Error())
				}
				return
			}

			decrypted, err := Decrypt(test.password, test.email, encrypted, test.kdf)
			if err != nil {
				if err.Error() != test.expectedError.Error() {
					t.Errorf("Expected error %q but got %q", test.expectedError.Error(), err.Error())
				}
				return
			}
			if decrypted != test.expected {
				t.Errorf("Expected %q but got %q", test.expected, encrypted)
			}
		})
	}
}

func TestDeriveMasterKey(t *testing.T) {
	tests := []struct {
		name        string
		password    []byte
		email       string
		kdf         types.KDFInfo
		expected    string
		expectedErr error
	}{
		{
			name:     "base case",
			password: []byte("password"),
			email:    "test@example.com",
			kdf: types.KDFInfo{
				Type:       types.KDFTypePBKDF2,
				Iterations: 1000,
			},
			expected:    "ZRutCjCltjwPo2il9HazrIn9+4t0r+5BI0lVv+Wktr0=",
			expectedErr: nil,
		},
		{
			name:     "base case with argon2id",
			password: []byte("password"),
			email:    "test@example.com",
			kdf: types.KDFInfo{
				Type:        types.KDFTypeArgon2id,
				Iterations:  10,
				Memory:      types.IntPtr(64),
				Parallelism: types.IntPtr(4),
			},
			expected:    "ng9/ltufpz8ZdLvrtnF13sKijz0alriaHQqu/4ChefQ=",
			expectedErr: nil,
		},
		{
			name:     "unsupported KDF type",
			password: []byte("password"),
			email:    "test@example.com",
			kdf: types.KDFInfo{
				Type:       999, // unsupported KDF type
				Iterations: 1000,
			},
			expected:    "",
			expectedErr: fmt.Errorf("unsupported KDF type %d", 999),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := DeriveMasterKey(test.password, test.email, test.kdf)
			if test.expectedErr != nil {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if err.Error() != test.expectedErr.Error() {
					t.Errorf("Expected error %q but got %q", test.expectedErr.Error(), err.Error())
				}
				return
			}

			var k string = base64.StdEncoding.EncodeToString(key)
			if err != nil {
				t.Errorf("Expected nil error but got %v", err)
			}

			if len(k) != len(test.expected) {
				t.Errorf("Expected key length %d but got %d", len(test.expected), len(key))
			}

			if k != test.expected {
				t.Errorf("Expected key byte %q but got %q", test.expected, k)
			}
		})
	}
}

func TestEncryptWith(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		password      []byte
		email         []byte
		cipherType    types.CipherStringType
		kdf           types.KDFInfo
		expectedError error
		mocks         *CryptoMock
		nilMac        bool
	}{
		{
			name:       "base case",
			data:       []byte("hello world"),
			password:   []byte("masterpw"),
			email:      []byte("email@example.com"),
			kdf:        types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherType: types.AesCbc256_HmacSha256_B64,
		},
		{
			name:       "base case with argon2id",
			data:       []byte("hello world"),
			password:   []byte("masterpw"),
			email:      []byte("email@example.com"),
			kdf:        types.KDFInfo{Type: types.KDFTypeArgon2id, Iterations: 10, Memory: types.IntPtr(64), Parallelism: types.IntPtr(4)},
			cipherType: types.AesCbc256_HmacSha256_B64,
		},
		{
			name:          "unsupported cipher type",
			data:          []byte("hello world"),
			password:      []byte("masterpw"),
			email:         []byte("email@example.com"),
			kdf:           types.KDFInfo{Type: types.KDFTypeArgon2id, Iterations: 10, Memory: types.IntPtr(64), Parallelism: types.IntPtr(4)},
			cipherType:    types.CipherStringType(999), // unsupported cipher type
			expectedError: fmt.Errorf("encrypt: unsupported cipher type %d", 0),
		},
		{
			name:          "unable to create new aes cipher",
			data:          []byte("hello world"),
			password:      []byte("masterpw"),
			email:         []byte("email@example.com"),
			kdf:           types.KDFInfo{Type: types.KDFTypeArgon2id, Iterations: 10, Memory: types.IntPtr(64), Parallelism: types.IntPtr(4)},
			cipherType:    types.AesCbc256_HmacSha256_B64,
			expectedError: fmt.Errorf("unable to create new aes cipher"),
			mocks: &CryptoMock{
				NewAesCipher: func(key []byte) (cipher.Block, error) {
					return nil, fmt.Errorf("unable to create new aes cipher")
				},
			},
		},
		{
			name:          "encrypt with cipher string type expects a MAC",
			data:          []byte("hello world"),
			password:      []byte("masterpw"),
			email:         []byte("email@example.com"),
			kdf:           types.KDFInfo{Type: types.KDFTypeArgon2id, Iterations: 10, Memory: types.IntPtr(64), Parallelism: types.IntPtr(4)},
			cipherType:    types.AesCbc256_HmacSha256_B64,
			expectedError: fmt.Errorf("encrypt: cipher string type expects a MAC"),
			nilMac:        true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)
			var (
				key, mac, decrypted []byte
				mpw                 []byte
				err                 error
			)

			setMocks(test.mocks)

			if mpw, err = DeriveMasterKey(test.password, string(test.email), test.kdf); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if key, mac, err = StretchKey(mpw); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if test.nilMac {
				mac = nil
			}

			encrypted, err := EncryptWith(test.data, test.cipherType, key, mac)
			if test.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error but got nil %v", mac)
				} else if err.Error() != test.expectedError.Error() {
					t.Errorf("Expected error %q but got %q", test.expectedError.Error(), err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected nil error but got %v", err)
			}

			decrypted, err = DecryptWith(encrypted, key, mac)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if string(decrypted) != string(test.data) {
				t.Fatalf("Expected %q but got %q", string(test.data), string(decrypted))
			}

		})
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

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		email         string
		kdf           types.KDFInfo
		cipherString  string
		expected      string
		expectedError error
		mocks         *CryptoMock
	}{
		{
			name:          "base case",
			password:      "masterpw",
			email:         "email@example.com",
			kdf:           types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherString:  "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4=",
			expected:      "hello world",
			expectedError: nil,
		},
		{
			name:          "decrypt with invalid mac",
			password:      "masterpw",
			email:         "email@example.com",
			kdf:           types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherString:  "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4=",
			expected:      "",
			expectedError: fmt.Errorf("decrypt: MAC mismatch 6 != 32"),
			mocks: &CryptoMock{
				Unmarshal: func(cs types.CipherString, text []byte) (types.CipherString, error) {
					err := cs.UnmarshalText(text)
					cs.MAC = []byte{1, 2, 3, 4, 5, 6}
					return cs, err
				},
			},
		},
		{
			name: "decrypt with missing mac",

			password:      "masterpw",
			email:         "email@example.com",
			kdf:           types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherString:  "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4=",
			expected:      "",
			expectedError: fmt.Errorf("decrypt: cipher string type expects a MAC"),
			mocks: &CryptoMock{
				Unmarshal: func(cs types.CipherString, text []byte) (types.CipherString, error) {
					err := cs.UnmarshalText(text)
					cs.MAC = []byte{}
					return cs, err
				},
			},
		},
		{
			name:          "decrypt fails to stretch master password",
			password:      "masterpw",
			email:         "email@example.com",
			kdf:           types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherString:  "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4=",
			expected:      "",
			expectedError: fmt.Errorf("unable to derive master password: unable to derive master key"),
			mocks: &CryptoMock{
				PbkdfKey: func(password []byte, salt []byte, iter int, keyLen int, hashFunc func() hash.Hash) []byte {
					return nil
				},
			},
		},
		{
			name:     "decrypt fails on unsupported KDF type",
			password: "masterpw",
			email:    "email@example.com",
			kdf: types.KDFInfo{
				Type:       999, // unsupported KDF type
				Iterations: 1000,
			},
			expected:      "",
			expectedError: fmt.Errorf("unable to derive master password: unsupported KDF type %d", 999),
		},
		{
			name:          "decrypt fails on unsupported cipher type",
			password:      "masterpw",
			email:         "email@example.com",
			kdf:           types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherString:  "999.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4=",
			expected:      "",
			expectedError: fmt.Errorf("unable to unmarshal cipher string: unsupported cipher string type or key length: %d", 999),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)
			setMocks(test.mocks)

			var (
				decrypted string
				err       error
			)

			decrypted, err = Decrypt(test.password, string(test.email), test.cipherString, test.kdf)
			if test.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if err.Error() != test.expectedError.Error() {
					t.Errorf("Expected error %q but got %q", test.expectedError.Error(), err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if string(decrypted) != test.expected {
				t.Fatalf("Expected %q but got %q", test.expected, string(decrypted))
			}
		})
	}
}

func TestDecryptWith(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		password      []byte
		email         []byte
		cipherString  string
		cipherType    types.CipherStringType
		kdf           types.KDFInfo
		expectedError error
		mocks         *CryptoMock
	}{
		{
			name:         "base case",
			data:         []byte("hello world"),
			password:     []byte("masterpw"),
			email:        []byte("email@example.com"),
			cipherString: "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4=",
			kdf:          types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherType:   types.AesCbc256_HmacSha256_B64,
		},
		{
			name:          "invalid cipher string type",
			data:          []byte("hello world"),
			password:      []byte("masterpw"),
			email:         []byte("email@example.com"),
			cipherString:  "2.MXGlACtpskXxMLTVQxT2gA==|macyrS8aApZ8roMxmHxCbQ==|moqXd+Yj14k7F+SQ8pScS0oJShShYMZIBo3/LksOdV4=",
			kdf:           types.KDFInfo{Type: types.KDFTypePBKDF2, Iterations: 800000},
			cipherType:    types.CipherStringType(999), // invalid cipher string type
			expectedError: fmt.Errorf("decrypt: unsupported cipher string type: %d", 999),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupSuite(t)(t)
			setMocks(test.mocks)

			var (
				key, mac, decrypted []byte
				mpw                 []byte
				err                 error
				cs                  types.CipherString
			)
			if err = cs.UnmarshalText([]byte(test.cipherString)); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if mpw, err = DeriveMasterKey(test.password, string(test.email), test.kdf); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if key, mac, err = StretchKey(mpw); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			cs.Type = test.cipherType

			decrypted, err = DecryptWith(cs, key, mac)
			if test.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if err.Error() != test.expectedError.Error() {
					t.Errorf("Expected error %q but got %q", test.expectedError.Error(), err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if string(decrypted) != string(test.data) {
				t.Fatalf("Expected %q but got %q", string(test.data), string(decrypted))
			}
		})
	}
}

func TestPadPKCS7(t *testing.T) {
	tests := []struct {
		name        string
		src         []byte
		size        int
		expected    []byte
		expectedErr error
	}{
		{
			name:        "hello padded to 8 bytes",
			src:         []byte("hello"),
			size:        8,
			expected:    []byte("hello\x03\x03\x03"),
			expectedErr: nil,
		},
		{
			name:        "world padded to 16 bytes",
			src:         []byte("world"),
			size:        16,
			expected:    []byte("world\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
			expectedErr: nil,
		},
		{
			name:        "tes padded to 4 bytes",
			src:         []byte("tes"),
			size:        4,
			expected:    []byte("tes\x01"),
			expectedErr: nil,
		},
		{
			name:     "over padding",
			src:      []byte("w^n}[,Taj6!XdESx\x01\x02\x03\x04\x05"),
			expected: nil,
			// 21 bytes in input string - add to 256 to trigger error
			size:        21 + 256,
			expectedErr: fmt.Errorf("cannot pad over %d bytes, but got %d", 255, 256),
		},
	}

	for _, tc := range tests {
		padded, err := PadPKCS7(tc.src, tc.size)
		if tc.expectedErr != nil {
			if err == nil {
				t.Errorf("Expected error but got nil")
			} else if err.Error() != tc.expectedErr.Error() {
				t.Errorf("Expected error %q but got %q", tc.expectedErr.Error(), err.Error())
			}
			continue
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
		size           int
	}{
		{
			name:           "base case",
			input:          []byte("w^n}[,Taj6!XdESx\x04\x04\x04\x04"),
			expectedOutput: []byte("w^n}[,Taj6!XdESx"),
			shouldErr:      false,
			size:           4,
		}, {
			name:           "too few pad bytes",
			input:          []byte("w^n}[,Taj6!XdESx\x04\x04\x04"),
			expectedOutput: nil,
			shouldErr:      true,
			size:           4,
		}, {
			name:           "unmatching pad bytes",
			input:          []byte("w^n}[,Taj6!XdESx\x01\x02\x03\x04\x05"),
			expectedOutput: nil,
			shouldErr:      true,
			size:           4,
		},
		{
			name:           "over padding",
			input:          []byte("w^n}[,Taj6!XdESx\x01\x02\x03\x04\x05"),
			expectedOutput: nil,
			shouldErr:      true,
			// 21 bytes in input string - add to 256 to trigger error
			size: func() int { return 21 + 256 }(),
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
