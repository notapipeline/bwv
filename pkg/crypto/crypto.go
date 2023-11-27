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
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/notapipeline/bwv/pkg/types"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

func DeriveMasterKey(password []byte, email string, kdf types.KDFInfo) ([]byte, error) {
	switch kdf.Type {
	case types.KDFTypePBKDF2:
		return pbkdf2.Key(password, []byte(strings.ToLower(email)), kdf.Iterations, 32, sha256.New), nil
	case types.KDFTypeArgon2id:
		var salt [32]byte = sha256.Sum256([]byte(strings.ToLower(email)))
		return argon2.IDKey(password, salt[:], uint32(kdf.Iterations),
			uint32(*kdf.Memory*1024), uint8(*kdf.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", kdf.Type)
	}
}

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

func EncryptWith(data []byte, csType types.CipherStringType, key, macKey []byte) (types.CipherString, error) {
	var (
		s     types.CipherString = types.CipherString{}
		block cipher.Block
		err   error
	)

	switch csType {
	case types.AesCbc256_B64, types.AesCbc256_HmacSha256_B64:
	default:
		return s, fmt.Errorf("encrypt: unsupported cipher type %q", s.Type)
	}
	s.Type = csType

	if data, err = PadPKCS7(data, aes.BlockSize); err != nil {
		return s, err
	}

	if block, err = aes.NewCipher(key); err != nil {
		return s, err
	}

	// Generate the IV
	s.IV = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(cryptorand.Reader, s.IV); err != nil {
		return s, err
	}

	// Generate the ciphertext
	s.CT = make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, s.IV)
	mode.CryptBlocks(s.CT, data)

	// If we require MAC, calculate it
	if csType == types.AesCbc256_HmacSha256_B64 {
		if len(macKey) == 0 {
			return s, fmt.Errorf("encrypt: cipher string type expects a MAC")
		}
		var macMessage []byte
		macMessage = append(macMessage, s.IV...)
		macMessage = append(macMessage, s.CT...)
		mac := hmac.New(sha256.New, macKey)
		mac.Write(macMessage)
		s.MAC = mac.Sum(nil)
	}

	return s, nil
}

func DecryptWith(s types.CipherString, key, macKey []byte) ([]byte, error) {
	var (
		block cipher.Block
		err   error
	)
	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	switch s.Type {
	case types.AesCbc256_B64, types.AesCbc256_HmacSha256_B64:
	default:
		return nil, fmt.Errorf("decrypt: unsupported cipher type %q", s.Type)
	}

	if s.Type == types.AesCbc256_HmacSha256_B64 {
		if len(s.MAC) == 0 || len(macKey) == 0 {
			return nil, fmt.Errorf("decrypt: cipher string type expects a MAC")
		}
		var msg []byte
		msg = append(msg, s.IV...)
		msg = append(msg, s.CT...)
		if !ValidMAC(msg, s.MAC, macKey) {
			return nil, fmt.Errorf("decrypt: MAC mismatch %d != %d", len(s.MAC), len(macKey))
		}
	}

	mode := cipher.NewCBCDecrypter(block, s.IV)
	dst := make([]byte, len(s.CT))
	mode.CryptBlocks(dst, s.CT)
	return UnpadPKCS7(dst, aes.BlockSize)
}

func UnpadPKCS7(src []byte, size int) ([]byte, error) {
	n := src[len(src)-1]
	if len(src)%size != 0 {
		return nil, fmt.Errorf("expected PKCS7 padding for block size %d, but have %d bytes", size, len(src))
	}
	src = src[:len(src)-int(n)]
	return src, nil
}

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

func ValidMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func StretchKey(orig []byte) (key, macKey []byte, err error) {
	key = make([]byte, 32)
	macKey = make([]byte, 32)
	var r io.Reader
	r = hkdf.Expand(sha256.New, orig, []byte("enc"))
	if _, err = r.Read(key); err != nil {
		return nil, nil, err
	}
	r = hkdf.Expand(sha256.New, orig, []byte("mac"))
	_, err = r.Read(macKey)
	return key, macKey, err
}
