/*
Package crypto provides cryptrographic functions the enciphering and deciphering
of AES 256 CBC encrypted data.

The provided functions are designed to be key secure and to avoid leaking
information about the key in memory. In practice, this means that the byte slice
containing the key is overwritten with cryptographically secure random data
after use.

Care must be taken that your real key is not overwritten and to achieve this
if calling this package without using the `SecretCache` then you must copy the
key before passing it to the `EncryptWith` or `DecryptWith` functions.

The safest way to achieve this is by using `memguard.Enclave` or similar to
cryptographically seal the key in memory.

	package main

	import (
		"github.com/awnumar/memguard"
		"github.com/notapipeline/bwv/pkg/crypto"
	)

	var keyEnclave *memguard.Enclave

	func storeKey(key []byte) {
		var buf *memguard.LockedBuffer = memguard.NewBuffer(32)
		defer buf.Destroy()
		buf.Move(key)
		keyEnclave = *buf.Seal()
	}

	func getKey() (kc []byte) {
		kb, err := keyEnclave.Open()
		if err != nil {
			panic(err)
		}
		defer kb.Destroy()
		kc = append(kc, kb.Bytes()...)
		return
	}

	func main() {
		var (
			password = []byte("masterpw")
			email = []byte("email@example.com")

			kdf = types.KDFInfo{
				Type: types.KDFTypePBKDF2,
				Iterations: 100000,
			}

			encData string = "2.IpXYBXvvIBNBewarXkBTng==|UB2u/0QeaJfs4ZDH52E2EA==|JakAHycn4TDU6cIV8yqOr/ik8oGP+rWTCYDBR17hKqg="
			cs types.CipherString = types.CipherString(encData)
		)

		key, mac, err := crypto.DeriveStretchedMasterKey(password, email, kdf)
		if err != nil {
			panic(err)
		}

		storeKey(key) // key has now been destroyed by being overwritten with random data

		// ... later on

		kc := getKey() // copy the key from the enclave
		decrypted, err := crypto.DecryptWith(encData, kc, mac) // key copy `kc` has now been destroyed
		if err != nil {
			panic(err)
		}

		fmt.Println(decrypted) // "password"
	}
*/
package crypto
