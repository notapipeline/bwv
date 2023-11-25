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
	Secrets []Secret
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
