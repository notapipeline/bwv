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

	FolderID            *uuid.UUID  `json:",omitempty"`
	OrganizationID      *uuid.UUID  `json:",omitempty"`
	Favorite            bool        `json:",omitempty"`
	Attachments         interface{} `json:",omitempty"`
	OrganizationUseTotp bool        `json:",omitempty"`
	CollectionIDs       []string    `json:",omitempty"`
	Fields              []Field     `json:",omitempty"`

	Card       *Card         `json:",omitempty"`
	Identity   *Identity     `json:",omitempty"`
	Login      *Login        `json:",omitempty"`
	Notes      *CipherString `json:",omitempty"`
	SecureNote *SecureNote   `json:",omitempty"`
}
