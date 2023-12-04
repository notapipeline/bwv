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
	"crypto/cipher"
	"hash"
	"io"

	"github.com/notapipeline/bwv/pkg/types"
)

type CryptoMock struct {
	PbkdfKey     func(password []byte, salt []byte, iter int, keyLen int, hashFunc func() hash.Hash) []byte
	Argon2ID     func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte
	HkdfExpand   func(hash func() hash.Hash, pseudorandomKey []byte, info []byte) io.Reader
	Unmarshal    func(cs types.CipherString, text []byte) (types.CipherString, error)
	NewAesCipher func(key []byte) (cipher.Block, error)
}
