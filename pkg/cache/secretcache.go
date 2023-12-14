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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"sync"

	"github.com/awnumar/memguard"

	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/types"
	"golang.org/x/crypto/pbkdf2"
)

// SecretCache is the main structural holding point for secret data retrieved
// from the Bitwarden servers.
//
// Initialization of this object is done in a singleton fashion to ensure data
// is not duplicated in memory. The master password is salted with the email
// address, passed through the number of iterations defined and stored in a
// memory guarded enclave. The master password is then cryptographically discarded.
type SecretCache struct {
	Data *types.DataFile

	keyEnclave *memguard.Enclave
	macKey     []byte
	KDF        types.KDFInfo

	mpEnclave *memguard.Enclave
}

var (
	secretCache *SecretCache
	lock        = &sync.Mutex{}
)

// Instance gets the current instance or creates a new secret cache object.
//
// When instantiating this object, the master password is salted with the email
// address, passed through the number of iterations defined and stored in locked
// memory. The master password is then discarded.
var Instance = instance
var MasterPassword = masterPassword

func instance(masterpw, email []byte, kdf types.KDFInfo) (*SecretCache, error) {
	lock.Lock()
	defer lock.Unlock()
	defer memguard.WipeBytes(masterpw)
	defer memguard.WipeBytes(email)

	if secretCache != nil {
		return secretCache, nil
	}

	secretCache = &SecretCache{
		KDF: kdf,
	}
	err := secretCache.setMasterPassword(masterpw, email)
	if err != nil {
		err = fmt.Errorf("failed to set master password: %v", err)
	}

	return secretCache, err
}

// Reset the secret cache
func Reset() {
	lock.Lock()
	defer lock.Unlock()
	memguard.Purge()
	secretCache = nil
}

func masterPassword() (b []byte, err error) {
	if secretCache == nil {
		return nil, fmt.Errorf("secret cache is not initialized")
	}
	var buf *memguard.LockedBuffer
	if buf, err = secretCache.mpEnclave.Open(); err != nil {
		log.Fatalf("failed to open enclave %q", err)
	}
	defer buf.Destroy()

	// We need to copy the buffer out otherwise it will be destroyed when the
	// function returns
	b = append(b, buf.Bytes()...)
	return
}

func (c *SecretCache) key() (b []byte, err error) {
	var buf *memguard.LockedBuffer
	if buf, err = c.keyEnclave.Open(); err != nil {
		err = fmt.Errorf("failed to open key enclave: %w", err)
	}
	defer buf.Destroy()

	b = append(b, buf.Bytes()...)
	return
}

// MasterPassword returns the master password used to unlock the secret cache.
func MasterPasswordKeyMac() ([]byte, []byte, error) {
	if secretCache == nil {
		return nil, nil, nil
	}
	mpw, err := MasterPassword()
	defer memguard.ScrambleBytes(mpw)
	if err != nil {
		return nil, nil, err
	}
	return crypto.StretchKey(mpw)
}

// Unlock the secret cache with the given key cipher.
//
// This method expects the User key as an encrypted CipherString as it is
// delivered from the Bitwarden server.
//
// This key can be found in both the Profile field of the data file as well as
// the LoginResponse.
func (c *SecretCache) Unlock(keyCipher types.CipherString) (err error) {
	// only unlock if there is nothing in the enclave (first time)
	if c.keyEnclave != nil {
		return
	}

	var (
		key, macKey, finalKey []byte
		mpw                   []byte
		scramble              bool
	)

	if mpw, err = MasterPassword(); err != nil {
		return
	}

	switch keyCipher.Type {
	case types.AesCbc256_B64:
		if finalKey, err = crypto.DecryptWith(keyCipher, mpw, nil); err != nil {
			scramble = true
		}
	case types.AesCbc256_HmacSha256_B64:
		// We decrypt the decryption key from the synced data, using the key
		// resulting from stretching masterKey. The keys are discarded once we
		// obtain the final ones.
		if key, macKey, err = crypto.StretchKey(mpw); err != nil {
			scramble = true
			break
		}

		if finalKey, err = crypto.DecryptWith(keyCipher, key, macKey); err != nil {
			scramble = true
		}
	default:
		err = fmt.Errorf("unsupported key cipher type %q", keyCipher.Type)
		scramble = true
	}

	var buf *memguard.LockedBuffer = memguard.NewBuffer(32)
	if !scramble {
		switch len(finalKey) {
		case 32:
			buf.Move(finalKey)
		case 64:
			c.macKey = append(c.macKey, finalKey[32:64]...)
			var b []byte
			b = append(b, finalKey[:32]...)
			buf.Move(b)
		default:
			err = fmt.Errorf("invalid key length: %d", len(finalKey))
		}

		if err == nil {
			enclave := buf.Seal()
			if enclave == nil {
				return fmt.Errorf("failed to create enclave for master password: %w", err)
			}

			c.keyEnclave = enclave
		}
	}

	// This copy of the key is done with and to prevent it being recovered from
	// memory it is scrambled to ensure it is not recoverable.
	memguard.ScrambleBytes(finalKey)
	memguard.ScrambleBytes(mpw)
	return
}

// Update the secret cache with the given data file.
func (c *SecretCache) Update(data *types.DataFile) (err error) {
	c.Data = data
	err = c.Unlock(data.Sync.Profile.Key)
	return
}

// HashPassword hashes the given password with the master password.
//
// This will destroy the password in memory after hashing.
func (c *SecretCache) HashPassword(password []byte) string {
	defer memguard.ScrambleBytes(password)
	var (
		err error
		mpw []byte
	)
	if mpw, err = MasterPassword(); err != nil {
		log.Fatalf("failed to get master password: %q", err)
	}

	hashedpw := base64.StdEncoding.
		Strict().
		EncodeToString(pbkdf2.Key(mpw, password, 1, 32, sha256.New))
	defer memguard.ScrambleBytes(mpw)
	return hashedpw
}

// DecryptStr takes a cipher string and decrypts it using the user key returning
// a string resopnse.
//
// This is a convenience method that wraps Decrypt.
func (c *SecretCache) DecryptStr(s types.CipherString) (ret string, err error) {
	var b []byte
	if b, err = c.Decrypt(s); err == nil {
		ret = string(b)
	}
	return
}

// Decrypt takes a cipher string and decrypts it using the user key returning a
// byte slice.
//
// This is a convenience method that wraps crypto.DecryptWith.
func (c *SecretCache) Decrypt(s types.CipherString) ([]byte, error) {
	if s.IsZero() {
		return nil, nil
	}

	var (
		key []byte
		err error
	)

	if key, err = c.key(); err != nil {
		return nil, err
	}
	defer memguard.ScrambleBytes(key)
	return crypto.DecryptWith(s, key, c.macKey)
}

// Encrypt takes a byte slice and encrypts it using the user key returning a
// cipher string.
//
// This is a convenience method that wraps crypto.EncryptWith.
func (c *SecretCache) Encrypt(data []byte) (types.CipherString, error) {
	return c.EncryptType(data, types.AesCbc256_HmacSha256_B64)
}

// EncryptType takes a byte slice and encrypts it using the user key returning a
// cipher string.
//
// This is a convenience method that wraps crypto.EncryptWith.
func (c *SecretCache) EncryptType(d []byte, t types.CipherStringType) (types.CipherString, error) {
	if len(d) == 0 {
		return types.CipherString{}, nil
	}

	var (
		key []byte
		err error
	)

	if key, err = c.key(); err != nil {
		return types.CipherString{}, err
	}
	defer memguard.ScrambleBytes(key)

	return crypto.EncryptWith(d, t, key, c.macKey)
}

// Set the master password into MLocked memory
func (c *SecretCache) setMasterPassword(password, email []byte) error {
	var (
		mpw []byte
		err error
	)

	if mpw, err = crypto.DeriveMasterKey([]byte(password), string(email), c.KDF); err != nil {
		return fmt.Errorf("failed to derive master password: %w", err)
	}

	buf := memguard.NewBuffer(len(mpw))
	buf.Move(mpw)
	enclave := buf.Seal()
	if enclave == nil {
		return fmt.Errorf("failed to create enclave for master password: %w", err)
	}
	c.mpEnclave = enclave
	return nil
}
