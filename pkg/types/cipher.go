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
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

func IntPtr(i int) *int {
	return &i
}

// {"kdf":0,"kdfIterations":100000,"kdfMemory":null,"kdfParallelism":null}
type KDFInfo struct {
	Type        KDFType `json:"kdf"`
	Iterations  int     `json:"kdfIterations"`
	Memory      *int    `json:"kdfMemory,omitempty"`
	Parallelism *int    `json:"kdfParallelism,omitempty"`
}

type SyncData struct {
	Profile Profile
	Folders []Folder
	Secrets []Secret `json:"Ciphers"`
}

type Secret struct {
	Type         SecretType
	ID           uuid.UUID
	Name         CipherString
	Edit         bool
	RevisionDate time.Time

	// The rest of the fields are optional. Omit from the JSON if empty.

	FolderID            *uuid.UUID   `json:",omitempty"`
	OrganizationID      *uuid.UUID   `json:",omitempty"`
	Favorite            bool         `json:",omitempty"`
	Attachments         []Attachment `json:",omitempty"`
	OrganizationUseTotp bool         `json:",omitempty"`
	CollectionIDs       []string     `json:",omitempty"`
	Fields              []Field      `json:",omitempty"`

	Card       *Card         `json:",omitempty"`
	Identity   *Identity     `json:",omitempty"`
	Login      *Login        `json:",omitempty"`
	Notes      *CipherString `json:",omitempty"`
	SecureNote *SecureNote   `json:",omitempty"`
}

type Attachment struct {
	FileName *CipherString `json:"fileName"`
	ID       string        `json:"id"`
	Key      *CipherString `json:"key"`
	Object   string        `json:"object"`
	Size     string        `json:"size"`
	SizeName string        `json:"sizeName"`
	URL      string        `json:"url"`
}

type SymmetricKey struct {
	Key    []byte
	EncKey []byte
	MacKey []byte

	Base64Key    string
	Base64EncKey string
	Base64MacKey string

	Meta any
}

func NewSymmetricKey(key []byte, keyType *CipherStringType) (*SymmetricKey, error) {
	k := &SymmetricKey{
		Key:          key,
		EncKey:       nil,
		MacKey:       nil,
		Base64Key:    "",
		Base64EncKey: "",
		Base64MacKey: "",
		Meta:         nil,
	}

	switch *keyType {
	case AesCbc256_B64:
		if len(key) != 32 {
			return nil, &InvalidKeyLengthError{Value: len(key), Type: *keyType}
		}
		k.EncKey = key
		k.MacKey = nil
	case AesCbc128_HmacSha256_B64:
		if len(key) != 32 {
			return nil, &InvalidKeyLengthError{Value: len(key), Type: *keyType}
		}
		k.EncKey = key[:16]
		k.MacKey = key[16:]
	case AesCbc256_HmacSha256_B64:
		if len(key) != 64 {
			return nil, &InvalidKeyLengthError{Value: len(key), Type: *keyType}
		}
		k.EncKey = key[:32]
		k.MacKey = key[32:]
	default:
		return nil, &UnsupportedTypeError{Value: int(*keyType)}
	}

	if k.Key != nil {
		k.Base64Key = base64.StdEncoding.EncodeToString(k.Key)
	}
	if k.EncKey != nil {
		k.Base64EncKey = base64.StdEncoding.EncodeToString(k.EncKey)
	}
	if k.MacKey != nil {
		k.Base64MacKey = base64.StdEncoding.EncodeToString(k.MacKey)
	}
	return k, nil
}

type PartialKey string

const (
	MasterAutoKey    PartialKey = "_masterkey_auto"
	BiometricKey     PartialKey = "_masterkey_biometric"
	MasterKey        PartialKey = "_masterkey"
	UserAutoKey      PartialKey = "_user_auto"
	UserBiometricKey PartialKey = "_user_biometric"
)
