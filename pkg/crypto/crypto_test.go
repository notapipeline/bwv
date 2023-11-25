package crypto

import (
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
