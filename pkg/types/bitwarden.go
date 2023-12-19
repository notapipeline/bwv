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

// Profile is the users profile information.
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

// URI is the URI associated with a login.
type URI struct {
	URI   string
	Match URIMatch
}

// SecureNote is an encrypted note attached to a secret.
type SecureNote struct {
	Type SecureNoteType
}

// UserDecryptionOptions are the options used to decrypt a user's data.
type UserDecryptionOptions struct {
	HasMasterPassword bool
	Object            string
}

// MasterPasswordPolicy is the policy used to enforce a master password.
type MasterPasswordPolicy map[string]interface{}

// LoginResponse is returned from the login endpoint. (POST /identity/connect/token)
type LoginResponse struct {
	KDFInfo
	MasterPasswordPolicy *MasterPasswordPolicy

	ForcePasswordReset    bool
	Key                   CipherString
	PrivateKey            CipherString
	ResetMasterPassword   bool
	TwoFactorToken        string
	UserDecryptionOptions *UserDecryptionOptions

	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

// DataFile is the data file stored in memory.
type DataFile struct {
	LoginResponse *LoginResponse
	DeviceID      string
	KDF           KDFInfo
	LastSync      time.Time
	Sync          SyncData
	Session       CipherString
}

// SecretResponse is returned between the `bwv` server and client
type SecretResponse struct {
	Message interface{} `json:"message" yaml:"message"`
}
