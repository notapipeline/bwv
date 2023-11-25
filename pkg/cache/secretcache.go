package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"syscall"

	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/types"
	"golang.org/x/crypto/pbkdf2"
)

type SecretCache struct {
	Data *types.DataFile

	key    []byte
	macKey []byte
	KDF    types.KDFInfo

	masterpw []byte
}

var (
	secretCache *SecretCache
	lock                             = &sync.Mutex{}
	mlock       func(b []byte) error = func(b []byte) error {
		return syscall.Mlock(b)
	}

	mcpy func(dst, src []byte) int = func(dst, src []byte) int {
		return copy(dst, src)
	}
)

// Instance gets the current instance or creates a new secret cache object.
//
// When instantiating this object, the master password is salted with the email
// address, passed through the number of iterations defined and stored in locked
// memory. The master password is then discarded.

var Instance = instance

func instance(masterpw, email string, kdf types.KDFInfo) (*SecretCache, error) {
	lock.Lock()
	defer lock.Unlock()
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
	secretCache = nil
}

// MasterPassword returns the master password used to unlock the secret cache.
func MasterPassword() []byte {
	return secretCache.masterpw
}

func (c *SecretCache) Unlock(keyCipher types.CipherString) (err error) {
	var (
		key, macKey, finalKey []byte
	)

	switch keyCipher.Type {
	case types.AesCbc256_B64:
		if finalKey, err = crypto.DecryptWith(keyCipher, c.masterpw, nil); err != nil {
			return
		}
	case types.AesCbc256_HmacSha256_B64:
		// We decrypt the decryption key from the synced data, using the key
		// resulting from stretching masterKey. The keys are discarded once we
		// obtain the final ones.
		if key, macKey, err = crypto.StretchKey(c.masterpw); err != nil {
			return
		}

		if finalKey, err = crypto.DecryptWith(keyCipher, key, macKey); err != nil {
			return
		}
	default:
		err = fmt.Errorf("unsupported key cipher type %q", keyCipher.Type)
		return
	}

	switch len(finalKey) {
	case 32:
		c.key = finalKey
	case 64:
		c.key, c.macKey = finalKey[:32], finalKey[32:64]
	default:
		err = fmt.Errorf("invalid key length: %d", len(finalKey))
	}

	return
}

func (c *SecretCache) Update(data types.DataFile) (err error) {
	c.Data = &data
	err = c.Unlock(data.Sync.Profile.Key)
	return
}

func (c *SecretCache) HashPassword(password string) string {
	hashedpw := base64.StdEncoding.
		Strict().
		EncodeToString(pbkdf2.Key(c.masterpw, []byte(password), 1, 32, sha256.New))
	return hashedpw
}

func (c *SecretCache) DecryptStr(s types.CipherString) (ret string, err error) {
	var b []byte
	if b, err = c.Decrypt(s); err == nil {
		ret = string(b)
	}
	return
}

func (c *SecretCache) Decrypt(s types.CipherString) ([]byte, error) {
	if s.IsZero() {
		return nil, nil
	}
	return crypto.DecryptWith(s, c.key, c.macKey)
}

func (c *SecretCache) Encrypt(data []byte) (types.CipherString, error) {
	return c.EncryptType(data, types.AesCbc256_HmacSha256_B64)
}

func (c *SecretCache) EncryptType(d []byte, t types.CipherStringType) (types.CipherString, error) {
	if len(d) == 0 {
		return types.CipherString{}, nil
	}
	return crypto.EncryptWith(d, t, c.key, c.macKey)
}

// Set the master password into MLocked memory
func (c *SecretCache) setMasterPassword(password, email string) error {
	mpw := pbkdf2.Key([]byte(password), []byte(email), c.KDF.Iterations, 32, sha256.New)
	c.masterpw = make([]byte, len(mpw))
	if err := mlock(c.masterpw); err != nil {
		return fmt.Errorf("failed to lock memory for master password: %w", err)
	}

	if l := mcpy(c.masterpw, mpw); l < len(mpw) {
		return fmt.Errorf("failed to set master password in locked memory. %d != %d", l, len(mpw))
	}
	return nil
}
