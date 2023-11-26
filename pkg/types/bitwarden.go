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

type KDFType int
type SecretType int
type FieldType int
type URIMatch int
type SecureNoteType int

// Organization is a Bitwarden organization.
type Organization struct {
	Object          string
	Id              uuid.UUID
	Name            string
	UseGroups       bool
	UseDirectory    bool
	UseEvents       bool
	UseTotp         bool
	Use2fa          bool
	UseApi          bool
	UsersGetPremium bool
	SelfHost        bool
	Seats           int
	MaxCollections  int
	MaxStorageGb    int
	Key             string
	Status          int
	Type            int
	Enabled         bool
}

// Profile is a Bitwarden profile.
type Profile struct {
	ID                 uuid.UUID
	Name               string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint string
	Culture            string
	TwoFactorEnabled   bool
	Key                CipherString
	PrivateKey         CipherString
	SecurityStamp      string
	Organizations      []Organization
}

// Folder is a Bitwarden folder.
type Folder struct {
	ID           uuid.UUID
	Name         CipherString
	RevisionDate time.Time
}

// Card describes a card stored as a Bitwarden secret.
type Card struct {
	CardholderName CipherString
	Brand          CipherString
	Number         CipherString
	ExpMonth       CipherString
	ExpYear        CipherString
	Code           CipherString
}

// Identity describes a personal identity stored as a Bitwarden secret.
type Identity struct {
	Title      CipherString
	FirstName  CipherString
	MiddleName CipherString
	LastName   CipherString

	Username       CipherString
	Company        CipherString
	SSN            CipherString
	PassportNumber CipherString
	LicenseNumber  CipherString

	Email      CipherString
	Phone      CipherString
	Address1   CipherString
	Address2   CipherString
	Address3   CipherString
	City       CipherString
	State      CipherString
	PostalCode CipherString
	Country    CipherString
}

// Field is a specific property type in a secret.
type Field struct {
	Type  FieldType
	Name  CipherString
	Value CipherString
}

// Login contains the login details of an account.
type Login struct {
	Password CipherString
	URI      CipherString
	URIs     []URI
	Username CipherString `json:",omitempty"`
	Totp     string       `json:",omitempty"`
}

type URI struct {
	URI   string
	Match URIMatch
}

// SecureNote is an encrypted note attached to a secret.
type SecureNote struct {
	Type SecureNoteType
}

type DataFile struct {
	DeviceID      string
	AccessToken   string
	RefreshToken  string
	TokenExpiry   time.Time
	KDF           int
	KDFIterations int

	LastSync time.Time
	Sync     SyncData
}
