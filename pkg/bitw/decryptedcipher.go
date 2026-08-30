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
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

// DecryptedCipher is a struct for holding decrypted cipher data.
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
	// Otp is the current TOTP code generated from the login's stored secret, if
	// it has one - not the secret itself.
	Otp string `json:"totp,omitempty"`

	// Notes is the free-text note attached to the item. Every cipher type can
	// carry one; a secure note is simply an item whose content is only this.
	Notes string `json:"notes,omitempty"`

	// Identity holds the decrypted attributes of an identity cipher, keyed by
	// the lowercase name they are queried under (firstname, postalcode, ...).
	// Only attributes the vault actually holds a value for are present.
	Identity map[string]string `json:"identity,omitempty"`

	// attachments will be sent b64encoded
	Attachments map[string]string `json:"attachments"`

	bwv *Bwv
}

// NewDecryptedCipher creates a new DecryptedCipher object.
func NewDecryptedCipher(b *Bwv) *DecryptedCipher {
	d := &DecryptedCipher{
		bwv: b,
	}
	return d
}

// Get returns the value of the given field.
func (d *DecryptedCipher) Get(what string) (value any) {
	what = strings.ToLower(what)
	if v, ok := d.meta(what); ok {
		return v
	}

	switch what {
	case "password":
		return d.Password
	case "otp", "totp":
		return d.Otp
	case "notes", "note":
		return d.Notes
	case "username":
		// An identity carries its own username; fall through to the identity
		// attributes below when the cipher has no login.
		if d.Username != "" {
			return d.Username
		}
	}

	if v, ok := d.Identity[what]; ok {
		return v
	}
	return nil
}

// meta returns the cipher's own attributes: the ones that are not strings, and
// so can never be shadowed by an identity attribute of the same name.
func (d *DecryptedCipher) meta(what string) (any, bool) {
	switch what {
	case "type":
		return d.Type, true
	case "id":
		return d.ID, true
	case "revisiondate":
		return d.RevisionDate, true
	case "name":
		return d.Name, true
	case "folderid":
		return d.FolderID, true
	case "organization":
		return d.OrganizationID, true
	}
	return nil, false
}

// identityFields pairs each attribute of an identity cipher with the name it is
// queried and rendered under. Bitwarden's identity schema is fixed, so this is
// all of it.
func identityFields(i *types.Identity) map[string]types.CipherString {
	return map[string]types.CipherString{
		"title":          i.Title,
		"firstname":      i.FirstName,
		"middlename":     i.MiddleName,
		"lastname":       i.LastName,
		"username":       i.Username,
		"company":        i.Company,
		"ssn":            i.SSN,
		"passportnumber": i.PassportNumber,
		"licensenumber":  i.LicenseNumber,
		"email":          i.Email,
		"phone":          i.Phone,
		"address1":       i.Address1,
		"address2":       i.Address2,
		"address3":       i.Address3,
		"city":           i.City,
		"state":          i.State,
		"postalcode":     i.PostalCode,
		"country":        i.Country,
	}
}

// decryptIdentity decrypts every populated attribute of an identity cipher.
func (d *DecryptedCipher) decryptIdentity(c types.Secret) {
	d.Identity = make(map[string]string)
	for name, cs := range identityFields(c.Identity) {
		if cs.IsZero() {
			continue
		}

		value, err := d.bwv.Secrets.DecryptCipherStr(cs, c.Key)
		if err != nil {
			log.Printf("[ERROR] cannot decrypt identity %s for cipher id=%s: %v", name, c.ID, err)
			continue
		}
		d.Identity[name] = value
	}
}

// decryptLogin decrypts the credentials of a login cipher, generating the
// current TOTP code when the login carries a secret.
func (d *DecryptedCipher) decryptLogin(c types.Secret) {
	var err error
	if d.Username, err = d.bwv.Secrets.DecryptCipherStr(c.Login.Username, c.Key); err != nil {
		log.Printf("[ERROR] cannot decrypt username for cipher id=%s: %v", c.ID, err)
	}

	if d.Password, err = d.bwv.Secrets.DecryptCipherStr(c.Login.Password, c.Key); err != nil {
		log.Printf("[ERROR] cannot decrypt password for cipher id=%s: %v", c.ID, err)
	}

	if c.Login.Totp.IsZero() {
		return
	}

	var secret string
	if secret, err = d.bwv.Secrets.DecryptCipherStr(c.Login.Totp, c.Key); err != nil {
		log.Printf("[ERROR] cannot decrypt TOTP secret for cipher id=%s: %v", c.ID, err)
		return
	}

	if d.Otp, err = totpCode(secret, time.Now()); err != nil {
		log.Printf("[ERROR] cannot generate TOTP for cipher id=%s: %v", c.ID, err)
		d.Otp = ""
	}
}

// GetAttachment returns the attachment with the given name.
func (d *DecryptedCipher) Decrypt(c types.Secret, name string) *DecryptedCipher {
	d.Type = int(c.Type)
	d.ID = c.ID
	d.Name = name
	d.RevisionDate = c.RevisionDate
	d.FolderID = c.FolderID
	d.OrganizationID = c.OrganizationID

	var fieldsMutex = sync.Mutex{}
	d.Fields = make(map[string]string)

	var attachmentsMutex = sync.Mutex{}
	d.Attachments = make(map[string]string)

	if c.Login != nil {
		d.decryptLogin(c)
	}

	if c.Identity != nil {
		d.decryptIdentity(c)
	}

	if c.Notes != nil && !c.Notes.IsZero() {
		var err error
		if d.Notes, err = d.bwv.Secrets.DecryptCipherStr(*c.Notes, c.Key); err != nil {
			log.Printf("[ERROR] cannot decrypt notes for cipher id=%s: %v", c.ID, err)
		}
	}

	var wg sync.WaitGroup
	for _, f := range c.Fields {
		wg.Add(1)
		go func(f types.Field) {
			defer wg.Done()
			d.decryptField(c, f, &fieldsMutex)
		}(f)
	}

	for _, a := range c.Attachments {
		wg.Add(1)
		go func(a types.Attachment) {
			defer wg.Done()
			d.decryptAttachment(c, a, &attachmentsMutex)
		}(a)
	}
	wg.Wait()
	return d
}

// decryptField decrypts one custom field and records it against its decrypted
// name.
func (d *DecryptedCipher) decryptField(c types.Secret, f types.Field, mu *sync.Mutex) {
	name, err := d.bwv.Secrets.DecryptCipherStr(f.Name, c.Key)
	if err != nil {
		log.Printf("[ERROR] cannot decrypt field name for cipher id=%s: %v", c.ID, err)
		return
	}

	value, err := d.bwv.Secrets.DecryptCipherStr(f.Value, c.Key)
	if err != nil {
		log.Printf("[ERROR] cannot decrypt field %q for cipher id=%s: %v", name, c.ID, err)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	d.Fields[name] = value
}

// decryptAttachment downloads and decrypts one attachment, recording it
// b64encoded against its decrypted filename.
func (d *DecryptedCipher) decryptAttachment(c types.Secret, a types.Attachment, mu *sync.Mutex) {
	var (
		size       int
		value      []byte
		attachment *types.Attachment
	)

	name, err := d.bwv.Secrets.DecryptCipherStr(*a.FileName, c.Key)
	if err != nil {
		log.Printf("[ERROR] cannot decrypt attachment name for cipher id=%s: %v", c.ID, err)
		return
	}

	// Although the attachment type is already stored in the cipher
	// this is not necessarily the correct location for the attachment.
	//
	// the real attachment needs to be queriied seperately
	if attachment, err = d.GetAttachmentLocation(c.ID.String(), a); err != nil {
		log.Println(err)
		return
	}

	if size, err = strconv.Atoi(attachment.Size); err != nil {
		log.Println(err)
		return
	}

	if value, err = d.DecryptUrl(attachment, size, c.Key); err != nil {
		log.Println(err)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	d.Attachments[name] = base64.StdEncoding.EncodeToString(value)
}

// GetAttachmentLocation queries the API to get the real location of the attachment.
func (d *DecryptedCipher) GetAttachmentLocation(c string, a types.Attachment) (*types.Attachment, error) {
	var (
		apiurl     = d.bwv.Endpoint.ApiServer + "/ciphers/" + c + "/attachment/" + a.ID
		req        *http.Request
		err        error
		ctx        = context.Background()
		attachment types.Attachment
	)

	// First query the API to get the real location of the attachment
	if req, err = http.NewRequest("GET", apiurl, nil); err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+d.bwv.Secrets.Data.LoginResponse.AccessToken)
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

// DecryptUrl takes an attachment and decrypts it. itemKey is the owning
// cipher's Key: when set, the attachment's data key is wrapped with the cipher
// key rather than the user key.
func (d *DecryptedCipher) DecryptUrl(attachment *types.Attachment, expectedSize int, itemKey *types.CipherString) ([]byte, error) {
	var (
		msg             types.SecretResponse
		decrypted, data []byte
		err             error
		req             *http.Request
		ctx             = context.Background()
		key, mac        []byte
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

	if key, err = d.bwv.Secrets.DecryptCipher(*attachment.Key, itemKey); err != nil {
		log.Println("error decrypting", attachment.URL, err)
		return nil, err
	}

	mac, key = key[32:], key[:32]
	if decrypted, err = crypto.DecryptAes(data, key, mac); err != nil {
		log.Println("error decrypting", attachment.URL, err)
		return nil, err
	}
	return decrypted, nil
}
