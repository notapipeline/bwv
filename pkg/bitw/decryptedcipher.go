/*
 *   Copyright 2022 Martin Proffitt <mproffitt@choclab.net>
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
package bitw

import (
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/notapipeline/bwv/pkg/types"
)

type DecryptedCipher struct {
	Type           int               `json:"type"`
	ID             uuid.UUID         `json:"id"`
	RevisionDate   time.Time         `json:"revision_date"`
	Name           string            `json:"name"`
	Fields         map[string]string `json:"fields"`
	FolderID       *uuid.UUID        `json:"folder_id,omitempty"`
	OrganizationID *uuid.UUID        `json:"org_id,omitempty"`

	Username string `json:"username"`
	Password string `json:"password"`
}

func (d *DecryptedCipher) Get(what string) (value interface{}) {
	switch strings.ToLower(what) {
	case "type":
		return d.Type
	case "id":
		return d.ID
	case "revisiondate":
		return d.RevisionDate
	case "name":
		return d.Name
	case "folderid":
		return d.FolderID
	case "organization":
		return d.OrganizationID
	case "username":
		return d.Username
	case "password":
		return d.Password
	}
	return nil
}

func decrypt(c types.Secret, name string) DecryptedCipher {
	d := DecryptedCipher{
		Type:           int(c.Type),
		ID:             c.ID,
		Name:           name,
		RevisionDate:   c.RevisionDate,
		FolderID:       c.FolderID,
		OrganizationID: c.OrganizationID,
	}

	var fieldsMutex = sync.Mutex{}
	d.Fields = make(map[string]string)

	if c.Login != nil {
		d.Username, _ = secrets.DecryptStr(c.Login.Username)
		d.Password, _ = secrets.DecryptStr(c.Login.Password)
	}

	var wg sync.WaitGroup
	for _, f := range c.Fields {
		wg.Add(1)
		go func(f types.Field) {
			defer wg.Done()
			name, _ := secrets.DecryptStr(f.Name)
			value, _ := secrets.DecryptStr(f.Value)
			fieldsMutex.Lock()
			d.Fields[name] = value
			fieldsMutex.Unlock()
		}(f)
	}
	wg.Wait()
	return d
}
