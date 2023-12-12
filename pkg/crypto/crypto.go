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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"math"
	"strings"

	"github.com/notapipeline/bwv/pkg/types"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	EncTypeLength = 1
	IVLength      = 16
	MACLength     = 32
	MinDataLength = 1
)

// Function references. These are used to allow for testing of the crypto
// functions. The variables can be modified during testing to allow for
// deterministic behaviour.
var (
	// variable for modifying pbkdf2 key behaviour during testing
	pbkdfKey func(password []byte, salt []byte, iter int, keyLen int, hashFunc func() hash.Hash) []byte = pbkdf2.Key

	// for modifying argon2 key behaviour during testing
	argon2ID func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte = argon2.IDKey

	// for modifying hkdf expansion behaviour during testing
	hkdfExpand func(hash func() hash.Hash, pseudorandomKey []byte, info []byte) io.Reader = hkdf.Expand

	// for modifying cipher string unmarshalling behaviour during testing
	unmarshal func(cs types.CipherString, text []byte) (types.CipherString, error) = func(cs types.CipherString, text []byte) (types.CipherString, error) {
		err := cs.UnmarshalText(text)
		return cs, err
	}

	// for new aes cipher creation during testing
	newAesCipher func(key []byte) (cipher.Block, error) = aes.NewCipher
)

// DeriveMasterKey derives the master key from the password and email address
//
// It achieves this by salting the password with the email and then using the
// KDF to derive the key.
//
// Currently there are two supported KDF methods:
//   - PBKDF2: https://en.wikipedia.org/wiki/PBKDF2
//   - Argon2id: https://en.wikipedia.org/wiki/Argon2
func DeriveMasterKey(password []byte, email string, kdf types.KDFInfo) (b []byte, err error) {
	switch kdf.Type {
	case types.KDFTypePBKDF2:
		b, err = pbkdfKey(password, []byte(strings.ToLower(email)), kdf.Iterations, 32, sha256.New), nil
	case types.KDFTypeArgon2id:
		var salt [32]byte = sha256.Sum256([]byte(strings.ToLower(email)))
		b, err = argon2ID(password, salt[:], uint32(kdf.Iterations),
			uint32(*kdf.Memory*1024), uint8(*kdf.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", kdf.Type)
	}
	if b == nil {
		err = fmt.Errorf("unable to derive master key")
	}
	return
}

// DeriveStretchedMasterKey derives the master key from the password and email address
//
// This is a wrapper function that supports stretching the master key using HKDF
// to generate two keys from the master key. The first is used for encryption and
// the second is used for MAC verification
func DeriveStretchedMasterKey(password []byte, email string, kdf types.KDFInfo) ([]byte, []byte, error) {
	var (
		key []byte
		err error
	)

	if key, err = DeriveMasterKey(password, email, kdf); err != nil {
		return nil, nil, err
	}

	return StretchKey(key)
}

// ClientEncrypt encrypts the given string using the password, salt and KDF
//
// It achieves this by first deriving the stretched master key and then using
// that to encrypt the string using AES-CBC-256 with HMAC-SHA256
func ClientEncrypt(password, salt, what string, kdf types.KDFInfo) (string, error) {
	var (
		key, mac []byte
		err      error
		t        types.CipherString
	)

	if key, mac, err = DeriveStretchedMasterKey([]byte(password), salt, kdf); err != nil {
		return "", fmt.Errorf("unable to stretch master password: %w", err)
	}

	if t, err = EncryptWith([]byte(what), types.AesCbc256_HmacSha256_B64, key, mac); err != nil {
		return "", fmt.Errorf("unable to encrypt cipher string: %w", err)
	}

	return t.String(), nil
}

// Encrypt encrypts the given input using the given key and mac key
//
// Only two cipher types are supported
//   - AES-CBC-256
//   - AES-CBC-256 with HMAC-SHA256
//
// mac is ignored if the cipher type is AES-CBC-256
//
// On successful encryption, a CipherString is returned which can then be
// safely marshalled to a string and transmitted in plain text.
func EncryptWith(data []byte, csType types.CipherStringType, key, macKey []byte) (s types.CipherString, err error) {
	switch csType {
	case types.AesCbc256_B64, types.AesCbc256_HmacSha256_B64:
	default:
		return s, fmt.Errorf("encrypt: unsupported cipher type %d", s.Type)
	}
	s.Type = csType

	s.IV, s.MAC, s.CT, err = encrypt(csType, data, key, macKey)
	return
}

// EncryptAes encrypts the given input using the given key and mac key
//
// This method should be used when the data is not to be provided as a
// CipherString such as that used for attachments
//
// On successful encryption, a byte slice is returned which can then be
// safely marshalled to a string and transmitted in plain text.
//
// The returned byte slice is a concatenation of the following:
//   - CipherStringType (1 byte)
//   - IV (16 bytes)
//   - MAC (32 bytes) (only if CipherStringType is AesCbc256_HmacSha256_B64)
//   - CT (variable length)
func EncryptAes(data []byte, csType types.CipherStringType, key, macKey []byte) ([]byte, error) {
	switch csType {
	case types.AesCbc256_B64, types.AesCbc256_HmacSha256_B64:
	default:
		return nil, fmt.Errorf("encrypt: unsupported cipher type %d", csType)
	}

	var (
		encType     []byte = []byte{byte(csType)}
		iv, mac, ct []byte
		err         error
	)
	if iv, mac, ct, err = encrypt(csType, data, key, macKey); err != nil {
		return nil, err
	}

	var msg []byte
	msg = append(msg, encType...)
	msg = append(msg, iv...)
	if csType == types.AesCbc256_HmacSha256_B64 {
		msg = append(msg, mac...)
	}
	msg = append(msg, ct...)
	return msg, nil
}

func encrypt(encType types.CipherStringType, data, key, keyMac []byte) (iv, mac, ct []byte, err error) {
	if data, err = PadPKCS7(data, aes.BlockSize); err != nil {
		return
	}

	var block cipher.Block
	if block, err = newAesCipher(key); err != nil {
		return
	}
	iv = make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(cryptorand.Reader, iv); err != nil {
		return
	}

	ct = make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, data)

	if encType == types.AesCbc256_HmacSha256_B64 {
		if len(keyMac) == 0 {
			err = fmt.Errorf("encrypt: cipher string type expects a MAC")
			return
		}
		var (
			msg   []byte
			mHash hash.Hash = hmac.New(sha256.New, keyMac)
		)
		msg = append(msg, iv...)
		msg = append(msg, ct...)
		if _, err = mHash.Write(msg); err != nil {
			return
		}
		mac = mHash.Sum(nil)
	}
	return
}

// Decrypt a given string using the password, salt and KDF
//
// `data` is expected to be a plaintext CipherString
//
// This function should only be used when the enciphered data is expected to be
// an ascii string. If the data is expected to be binary, use DecryptWith or
// DecryptAes
func Decrypt(password, salt, data string, kdf types.KDFInfo) (string, error) {
	var (
		key, mac []byte
		err      error
		cs       types.CipherString
		b        []byte
	)
	if cs, err = unmarshal(cs, []byte(data)); err != nil {
		return "", fmt.Errorf("unable to unmarshal cipher string: %w", err)
	}

	if key, mac, err = DeriveStretchedMasterKey([]byte(password), salt, kdf); err != nil {
		return "", fmt.Errorf("unable to derive master password: %w", err)
	}

	b, err = DecryptWith(cs, key, mac)
	return string(b), err
}

// DecryptWith decrypts the given CipherString using the given key and mac key
//
// Only two cipher types are supported
//   - AES-CBC-256
//   - AES-CBC-256 with HMAC-SHA256
//
// mac is ignored if the cipher type is AES-CBC-256
//
// On successful decryption, the plaintext is returned as a byte slice
func DecryptWith(s types.CipherString, key, keyMac []byte) ([]byte, error) {
	switch s.Type {
	case types.AesCbc256_B64, types.AesCbc256_HmacSha256_B64:
	default:
		return nil, fmt.Errorf("decrypt: unsupported cipher string type: %d", s.Type)
	}

	return decrypt(s.Type, s.IV, s.MAC, s.CT, key, keyMac)
}

// DecryptAes decrypts the given byte slice using the given key and mac key
//
// This method should be used when the data is not provided as a CipherString
// such as that used for attachments
func DecryptAes(data []byte, key, keyMac []byte) ([]byte, error) {
	var (
		iv, mac, ct []byte
		encType     types.CipherStringType = types.CipherStringType(data[0])
	)

	switch encType {
	case types.AesCbc128_HmacSha256_B64, types.AesCbc256_HmacSha256_B64:
		if len(data) < EncTypeLength+IVLength+MACLength+MinDataLength {
			return nil, fmt.Errorf("decrypt: data too short")
		}
		iv = data[EncTypeLength : EncTypeLength+IVLength]
		mac = data[EncTypeLength+IVLength : EncTypeLength+IVLength+MACLength]
		ct = data[EncTypeLength+IVLength+MACLength:]
	case types.AesCbc256_B64:
		if len(data) < EncTypeLength+IVLength+MinDataLength {
			return nil, fmt.Errorf("decrypt: data too short")
		}
		iv = data[EncTypeLength : EncTypeLength+IVLength]
		ct = data[EncTypeLength+IVLength:]
	default:
		return nil, fmt.Errorf("decrypt: unsupported cipher string type: %d", encType)
	}

	return decrypt(encType, iv, mac, ct, key, keyMac)
}

func decrypt(encType types.CipherStringType, iv, mac, ct, key, keyMac []byte) ([]byte, error) {
	var (
		block cipher.Block
		err   error
	)

	if block, err = newAesCipher(key); err != nil {
		return nil, err
	}

	switch encType {
	case types.AesCbc128_HmacSha256_B64, types.AesCbc256_HmacSha256_B64:
		if len(mac) == 0 || len(keyMac) == 0 {
			return nil, fmt.Errorf("decrypt: cipher string type expects a MAC")
		}
		var msg []byte
		msg = append(msg, iv...)
		msg = append(msg, ct...)
		if !ValidMAC(msg, mac, keyMac) {
			var mm, km string
			mm = base64.StdEncoding.EncodeToString(mac)
			km = base64.StdEncoding.EncodeToString(keyMac)
			return nil, fmt.Errorf("decrypt: MAC mismatch %q != %q", mm, km)
		}
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	dst := make([]byte, len(ct))
	mode.CryptBlocks(dst, ct)
	return UnpadPKCS7(dst, aes.BlockSize)
}

// UnpadPKCS7 removes the PKCS7 padding from the given byte slice
func UnpadPKCS7(src []byte, size int) ([]byte, error) {
	n := src[len(src)-1]
	if len(src)%size != 0 {
		return nil, fmt.Errorf("expected PKCS7 padding for block size %d, but have %d bytes", size, len(src))
	}
	src = src[:len(src)-int(n)]
	return src, nil
}

// PadPKCS7 adds PKCS7 padding to the given byte slice
func PadPKCS7(src []byte, size int) ([]byte, error) {
	rem := len(src) % size
	n := size - rem
	if n > math.MaxUint8 {
		return nil, fmt.Errorf("cannot pad over %d bytes, but got %d", math.MaxUint8, n)
	}
	padded := make([]byte, len(src)+n)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded, nil
}

// ValidMAC reports whether messageMAC is a valid HMAC tag for message.
func ValidMAC(message, messageMAC, keyMac []byte) bool {
	mac := hmac.New(sha256.New, keyMac)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// StretchKey stretches the given key using HKDF and returns the key and mac key
func StretchKey(orig []byte) (key, macKey []byte, err error) {
	key = make([]byte, 32)
	macKey = make([]byte, 32)
	var r io.Reader
	r = hkdfExpand(sha256.New, orig, []byte("enc"))
	if _, err = r.Read(key); err != nil {
		return nil, nil, err
	}
	r = hkdfExpand(sha256.New, orig, []byte("mac"))
	_, err = r.Read(macKey)
	return key, macKey, err
}
