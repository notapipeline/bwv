// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// This file is covered by the license at https://github.com/mvdan/bitw/blob/master/LICENSE
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

func EncryptWith(data []byte, csType types.CipherStringType, key, macKey []byte) (types.CipherString, error) {
	s := types.CipherString{}
	switch csType {
	case types.AesCbc256_B64, types.AesCbc256_HmacSha256_B64:
	default:
		return s, fmt.Errorf("encrypt: unsupported cipher type %q", s.Type)
	}
	s.Type = csType

	data = PadPKCS7(data, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
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
	block, err := aes.NewCipher(key)
	if err != nil {
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
			return nil, fmt.Errorf("decrypt: MAC mismatch")
		}
	}

	mode := cipher.NewCBCDecrypter(block, s.IV)
	dst := make([]byte, len(s.CT))
	mode.CryptBlocks(dst, s.CT)
	dst, err = UnpadPKCS7(dst, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func UnpadPKCS7(src []byte, size int) ([]byte, error) {
	n := src[len(src)-1]
	if len(src)%size != 0 {
		return nil, fmt.Errorf("expected PKCS7 padding for block size %d, but have %d bytes", size, len(src))
	}
	if len(src) <= int(n) {
		return nil, fmt.Errorf("cannot unpad %d bytes out of a total of %d", n, len(src))
	}
	src = src[:len(src)-int(n)]
	return src, nil
}

func PadPKCS7(src []byte, size int) []byte {
	// Note that we always pad, even if rem==0. This is because unpad must
	// always remove at least one byte to be unambiguous.
	rem := len(src) % size
	n := size - rem
	if n > math.MaxUint8 {
		panic(fmt.Sprintf("cannot pad over %d bytes, but got %d", math.MaxUint8, n))
	}
	padded := make([]byte, len(src)+n)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
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
