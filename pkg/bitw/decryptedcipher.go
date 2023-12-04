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
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/transport"
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

	// attachments will be sent b64encoded
	Attachments map[string]string `json:"attachments"`
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

	var attachmentsMutex = sync.Mutex{}
	d.Attachments = make(map[string]string)

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

	for _, a := range c.Attachments {
		wg.Add(1)
		go func(a types.Attachment) {
			defer wg.Done()
			name, _ := secrets.DecryptStr(*a.FileName)
			var (
				size       int
				err        error
				value      []byte
				attachment *types.Attachment
			)

			if attachment, err = GetAttachmentLocation(c.ID.String(), a); err != nil {
				log.Println(err)
				return
			}

			if size, err = strconv.Atoi(attachment.Size); err != nil {
				log.Println(err)
				return
			}

			if value, _ = DecryptUrl(attachment, size); err != nil {
				log.Println(err)
				return
			}
			attachmentsMutex.Lock()
			d.Attachments[name] = base64.StdEncoding.EncodeToString(value)
			attachmentsMutex.Unlock()
		}(a)
	}
	wg.Wait()
	return d
}

func GetAttachmentLocation(c string, a types.Attachment) (*types.Attachment, error) {
	var (
		apiurl     string = Endpoint.ApiServer + "/ciphers/" + c + "/attachment/" + a.ID
		req        *http.Request
		err        error
		ctx        context.Context = context.Background()
		attachment types.Attachment
	)

	// First query the API to get the real location of the attachment
	if req, err = http.NewRequest("GET", apiurl, nil); err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+secrets.Data.LoginResponse.AccessToken)
	log.Println("sending request to", apiurl)
	if err = transport.DefaultHttpClient.DoWithBackoff(ctx, req, &attachment); err != nil {
		log.Println("error sending request to", apiurl, err)
		if _, ok := err.(*json.UnmarshalTypeError); !ok {
			return nil, err
		}

		if _, ok := err.(*transport.ErrNotFound); !ok {
			// fall back to the original attachment and fail from there
			return &a, err
		}
	}
	return &attachment, nil
}

func DecryptUrl(attachment *types.Attachment, expectedSize int) ([]byte, error) {
	var (
		msg              types.SecretResponse
		decrypted, data  []byte
		err              error
		req              *http.Request
		ctx              context.Context = context.Background()
		userKey, userMac []byte          = cache.UserKey()
		key, mac         []byte
	)

	if req, err = http.NewRequest("GET", attachment.URL, nil); err != nil {
		return nil, err
	}
	req.Header.Set("cache-control", "no-cache")

	log.Println("sending request to", attachment.URL)
	if err = transport.DefaultHttpClient.DoWithBackoff(ctx, req, &msg); err != nil {
		log.Println("error sending request to", attachment.URL, err)
		return nil, err
	}

	if data, err = base64.StdEncoding.DecodeString(msg.Message.(string)); err != nil {
		return nil, err
	}

	if len(data) != expectedSize {
		log.Printf("received %d bytes from %s expected %d\n", len(data), attachment.URL, expectedSize)
		return nil, err
	}

	if key, err = crypto.DecryptWith(*attachment.Key, userKey, userMac); err != nil {
		log.Println("error decrypting", attachment.URL, err)
		return nil, err
	}

	mac = key[32:]
	key = key[:32]

	if decrypted, err = crypto.DecryptAes(data, key, mac); err != nil {
		log.Println("error decrypting", attachment.URL, err)
		return nil, err
	}
	return decrypted, nil
}
