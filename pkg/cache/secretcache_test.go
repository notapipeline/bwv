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
package cache

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/notapipeline/bwv/pkg/types"
)

var pbkdf types.KDFInfo = types.KDFInfo{
	Type:        types.KDFTypePBKDF2,
	Iterations:  800000,
	Memory:      types.IntPtr(0),
	Parallelism: types.IntPtr(0),
}

/*var argon2 types.KDFInfo = types.KDFInfo{
	Type:        :types.Argon2id,
	Iterations:  :1,
	Memory:      :65536,
	Parallelism: :4,
}*/

func setupSuite(t *testing.T) func(t *testing.T) {
	return func(t *testing.T) {
		Reset()
		mlock = func(b []byte) error {
			return syscall.Mlock(b)
		}
		mcpy = func(dst, src []byte) int {
			return copy(dst, src)
		}
	}
}

func TestInstanceReturnSameInstance(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	// Call the Instance function
	cache, _ := Instance("masterpw", "email", pbkdf)
	secretCache, _ := Instance("masterpw", "email", pbkdf)

	// Verify that the returned cache is the same as the initialized secretCache
	if cache != secretCache {
		t.Errorf("Expected %+v but got %+v", secretCache, cache)
	}
}

func TestInstancePassword(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	// Call the Instance function
	cache, _ := Instance("masterpw", "email", pbkdf)

	var (
		expectedPasswd string = "w\x0eK\xc6\x0er\xd6eg\xce\xec\r\n\xebAN\xa1\x80\"\x96=hN\x15\x8d\x98\xfe\xac\v\xdcT\x1d"
		receivedPasswd string = string(MasterPassword())
		expected       string = "CCjdBXfDr1pZDn29R998UsQsLkqkadyk27CFlhUxDEk="
		received       string = cache.HashPassword("masterpw")
	)
	if expectedPasswd != receivedPasswd {
		t.Errorf("Expected %q but got %q", expectedPasswd, receivedPasswd)
	}
	// Verify that the returned cache is the same as the initialized secretCache
	if received != expected {
		t.Errorf("Expected %q but got %q", expected, received)
	}
}

func TestInstancePasswordReturnsErrorIfNoMlock(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	mlock = func(b []byte) error {
		return fmt.Errorf("no mlock")
	}
	// Call the Instance function
	_, err := Instance("masterpw", "email", pbkdf)

	// Verify that the returned cache is the same as the initialized secretCache
	var message string = "failed to set master password: " +
		"failed to lock memory for master password: no mlock"
	if err == nil {
		t.Errorf("Expected nil but got %q", err)
	}

	if err.Error() != message {
		t.Errorf("Expected %q but got %q", message, err.Error())
	}
}

func TestInstancePasswordReturnsErrorIfMemCopyDoesntMatch(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)
	mcpy = func(dst, src []byte) int {
		return 0
	}
	// Call the Instance function
	_, err := Instance("masterpw", "email", pbkdf)

	// Verify that the returned cache is the same as the initialized secretCache
	var message string = "failed to set master password: " +
		"failed to set master password in locked memory. 0 != 32"
	if err == nil {
		t.Errorf("Expected nil but got %q", err)
	}

	if err.Error() != message {
		t.Errorf("Expected %q but got %q", message, err.Error())
	}
}

// To generate the unlock key (cs) the following steps are taken:
// 1. Get the stretch key (k, m) from the master password
// 2. Append the mac key (m) to the stretch key (k) (append(k, m...))
// 3. set secretCache.key = k and secretCache.macKey = m
// 4. encrypt the appended key (append(k, m...)) with the cs and log the result
func TestEncryptDecryptAesCbc256HmacSha256B64(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	// Call the Instance function
	cache, _ := Instance("masterpw", "email@example.com", pbkdf)

	var (
		expected                string = "test"
		encrypted               types.CipherString
		cs                      types.CipherString
		encryptedMasterPassword string = "2.i/7aEu9Pc3WI8hvaADB/Fg==|" +
			"gFxSM2jOaUbJpfYharUTX/OEEnUHSwDoLEZKXt1bAAxAhZpxaj8zE/" +
			"19tiC7o12BRwPpydQb7bjmGDIG8unMNpt9rL29N83qY8tmfQCtMeA=|" +
			"uhT83UtbUx8Ls2NYHFUh8ny5a4vdAObg/7aLWJeYtH4="
	)
	if err := cs.UnmarshalText([]byte(encryptedMasterPassword)); err != nil {
		t.Errorf("Expected nil error but got %v when unmarshalling master password to CipherString", err)
	}

	if err := cache.Unlock(cs); err != nil {
		t.Errorf("Expected nil error but got %v when unlocking", err)
	}

	encrypted, err := cache.Encrypt([]byte("test"))
	if err != nil {
		t.Errorf("Expected nil error but got %v when encrypting", err)
	}

	received, err := cache.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Expected nil error but got %v when decrypting", err)
	}

	if string(received) != expected {
		t.Errorf("Expected %q but got %q when decrypting", expected, string(received))
	}
}
func TestEncryptDecryptAesCbc256B64(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	// Call the Instance function
	cache, _ := Instance("masterpw", "email@example.com", pbkdf)

	var (
		encryptedMasterPassword = "0.NayR3jdlY9tNpp6YEMtP2Q==|" +
			"PW/yzOubp8jBegTvyb88zkVmSStPULi1UqLNiPOiezjjXdOyOkTr4CLW5BLolfza"
		expected  string = "test"
		encrypted types.CipherString
		cs        types.CipherString
	)

	if err := cs.UnmarshalText([]byte(encryptedMasterPassword)); err != nil {
		t.Errorf("Expected nil error but got %v when unmarshalling master password to CipherString", err)
	}

	if err := cache.Unlock(cs); err != nil {
		t.Errorf("Expected nil error but got %v when unlocking", err)
	}

	encrypted, err := cache.EncryptType([]byte("test"), types.AesCbc256_B64)
	if err != nil {
		t.Errorf("Expected nil error but got %v when encrypting", err)
	}

	received, err := cache.DecryptStr(encrypted)
	if err != nil {
		t.Errorf("Expected nil error but got %v when decrypting", err)
	}

	if received != expected {
		t.Errorf("Expected %q but got %q when decrypting", expected, received)
	}
}

func TestRequestDecryptionAndEncryptionWithZeroBytes(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	// Call the Instance function
	cache, _ := Instance("masterpw", "email@example.com", pbkdf)
	var (
		encrypted               types.CipherString
		cs                      types.CipherString
		encryptedMasterPassword string = "2.i/7aEu9Pc3WI8hvaADB/Fg==|" +
			"gFxSM2jOaUbJpfYharUTX/OEEnUHSwDoLEZKXt1bAAxAhZpxaj8zE/" +
			"19tiC7o12BRwPpydQb7bjmGDIG8unMNpt9rL29N83qY8tmfQCtMeA=|" +
			"uhT83UtbUx8Ls2NYHFUh8ny5a4vdAObg/7aLWJeYtH4="
	)
	if err := cs.UnmarshalText([]byte(encryptedMasterPassword)); err != nil {
		t.Errorf("Expected nil error but got %v when unmarshalling master password to CipherString", err)
	}

	if err := cache.Unlock(cs); err != nil {
		t.Errorf("Expected nil error but got %v when unlocking", err)
	}

	encrypted, _ = cache.Encrypt([]byte(""))
	if !encrypted.IsZero() {
		t.Errorf("Expected zero CipherString but got %v", encrypted)
	}

	if b, _ := cache.Decrypt(encrypted); b != nil {
		t.Errorf("Expected zero CipherString but got %v", encrypted)
	}
}
