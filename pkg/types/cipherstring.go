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
	"encoding/base64"
	"fmt"
	"strconv"
)

var b64enc = base64.StdEncoding.Strict()

// CipherString - nearly everythfing in this protocol is encrypted. This is the
// structure that holds that encrypted data.
//
// The format is:
//
//	<type>.<iv>|<ct>[|<mac>]
//
// Where:
//
//		<type> is the CipherStringType - integer format
//		  0 = AesCbc256_B64
//		  1 = AesCbc128_HmacSha256_B64
//		  2 = AesCbc256_HmacSha256_B64
//		<iv> is the initialization vector - base64 encoded - Decoded length is 16 bytes
//		<ct> is the ciphertext - base64 encoded - Decoded length is arbitrary
//		<mac> is the message authentication code - base64 encoded (optional
//	          depending on type) - Decoded length is 16 or 32 bytes
type CipherString struct {
	Type CipherStringType

	IV, CT, MAC []byte
}

// CipherStringType - Each cipher string has a type. Normally this will be one of
// the AesCbc* types.
//
// In general, only two types are used:
//
//	AesCbc256_B64
//	AesCbc256_HmacSha256_B64
//
// Within these, for current versions of Bitwarden, only AesCbc256_HmacSha256_B64
// is used.
type CipherStringType int

// HasMac - returns true if the cipher string type has a MAC
func (t CipherStringType) HasMAC() bool {
	return t != AesCbc256_B64
}

// Atoi - convert a byte slice to a CipherStringType
func (t CipherStringType) Atoi(b []byte) (CipherStringType, error) {
	v, err := strconv.Atoi(string(b))
	return CipherStringType(v), err
}

// String - convert a CipherStringType to a string
func (t CipherStringType) String() string {
	switch t {
	case AesCbc256_B64:
		return "AesCbc256_B64"
	case AesCbc128_HmacSha256_B64:
		return "AesCbc128_HmacSha256_B64"
	case AesCbc256_HmacSha256_B64:
		return "AesCbc256_HmacSha256_B64"
	}
	return fmt.Sprintf("CipherStringType(%d)", t)
}

// IsZero - returns true if the CipherString is empty
func (s CipherString) IsZero() bool {
	return s.Type == 0 && s.IV == nil && s.CT == nil && s.MAC == nil
}

// MarshalText - convert a CipherString to a byte slice
func (s CipherString) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// String - convert a CipherString to a string
func (s CipherString) String() string {
	if s.IsZero() {
		return ""
	}
	if !s.Type.HasMAC() {
		return fmt.Sprintf("%d.%s|%s",
			s.Type,
			b64enc.EncodeToString(s.IV),
			b64enc.EncodeToString(s.CT),
		)
	}
	return fmt.Sprintf("%d.%s|%s|%s",
		s.Type,
		b64enc.EncodeToString(s.IV),
		b64enc.EncodeToString(s.CT),
		b64enc.EncodeToString(s.MAC),
	)
}

func (s CipherString) Bytes() []byte {
	return []byte(s.String())
}

// UnmarshalText - convert a byte slice to a CipherString
func (s *CipherString) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	var (
		i        int
		err      error
		expected int
	)

	if i = bytes.IndexByte(data, '.'); i < 0 {
		return MissingTypeError{Value: data}
	}

	if s.Type, err = s.Type.Atoi(data[:i]); err != nil {
		return InvalidTypeError{Value: data[:i]}
	}

	switch s.Type {
	case AesCbc256_B64, AesCbc128_HmacSha256_B64, AesCbc256_HmacSha256_B64:
	default:
		return UnsupportedTypeError{Value: int(s.Type)}
	}

	data = data[(i + 1):]
	parts := bytes.Split(data, []byte(SEPARATOR))

	expected = WITHOUT_MAC
	if s.Type.HasMAC() {
		expected = WITH_MAC
	}

	if len(parts) != expected {
		return fmt.Errorf("cipher string type requires %d parts: %q", expected, data)
	}

	if s.IV, err = b64decode(parts[0]); err != nil {
		return err
	}
	if s.CT, err = b64decode(parts[1]); err != nil {
		return err
	}
	if s.Type.HasMAC() {
		if s.MAC, err = b64decode(parts[2]); err != nil {
			return err
		}
	}
	return nil
}

func b64decode(src []byte) (dst []byte, err error) {
	var n int
	dst = make([]byte, b64enc.DecodedLen(len(src)))
	if n, err = b64enc.Decode(dst, src); err != nil {
		return nil, err
	}
	dst = dst[:n]
	return
}
