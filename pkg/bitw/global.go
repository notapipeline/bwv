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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

const CHUNKSIZE int = 5

var (
	globalData DataFile
	saveData   bool
	secrets    secretCache
	masterpw   []byte

	apiURL = "https://api.bitwarden.com"
	idtURL = "https://identity.bitwarden.com"

	ApiServer string
	IdtServer string
	EmailAddr string
)

func DeriveHttpGetAPIKey(partial string) string {
	return base64.StdEncoding.EncodeToString(deriveMasterKey(masterpw, partial, 1))
}

func init() { secrets.data = &globalData }

type DataFile struct {
	path string

	DeviceID      string
	AccessToken   string
	RefreshToken  string
	TokenExpiry   time.Time
	KDF           int
	KDFIterations int

	LastSync time.Time
	Sync     SyncData
}

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

func Prelogin(email string) (*preLoginResponse, error) {
	var preLogin preLoginResponse
	if err := jsonPOST(context.Background(), apiURL+"/accounts/prelogin", &preLogin, preLoginRequest{
		Email: email,
	}); err != nil {
		return nil, fmt.Errorf("Could not retrieve pre-login data: %v", err)
	}
	globalData.KDF = preLogin.KDF
	globalData.KDFIterations = preLogin.KDFIterations
	return &preLogin, nil
}

func SetMasterPassword(password, email string, plr *preLoginResponse) string {
	mpw := pbkdf2.Key([]byte(password), []byte(email), plr.KDFIterations, 32, sha256.New)
	masterpw = make([]byte, len(mpw))
	if err := syscall.Mlock(masterpw); err != nil {
		log.Fatal("Failed to lock memory for master password")
	}
	for i, b := range mpw {
		masterpw[i] = b
	}

	hashedpw := base64.StdEncoding.Strict().EncodeToString(pbkdf2.Key(masterpw, []byte(password), 1, 32, sha256.New))
	return hashedpw
}

func ApiLogin(clientId, clientSecret string) (*LoginResponse, error) {
	var lr LoginResponse
	login := urlValues(
		"grant_type", "client_credentials",
		"scope", "api",
		"client_id", clientId,
		"client_secret", clientSecret,
		"deviceType", "3",
		"deviceIdentifier", "aac2e34a-44db-42ab-a733-5322dd582c3d",
		"deviceName", "firefox",
	)
	err := jsonPOST(context.Background(), idtURL+"/connect/token", &lr, login)
	if err != nil {
		return nil, err
	}

	return &lr, nil
}

func UserLogin(hashedPassword, email string) (*LoginResponse, error) {
	var lr LoginResponse
	login := urlValues(
		"grant_type", "password",
		"username", email,
		"password", hashedPassword,
		"scope", "api",
		"client_id", "browser",
		"deviceType", "3",
		"deviceIdentifier", "aac2e34a-44db-42ab-a733-5322dd582c3d",
		"deviceName", "firefox",
	)

	ctx := context.Background()
	if err := jsonPOST(ctx, idtURL+"/connect/token", &lr, login); err != nil {
		var (
			errsc *errStatusCode
			ok    bool
		)
		if errsc, ok = err.(*errStatusCode); !ok {
			return nil, err
		}

		if !bytes.Contains(errsc.body, []byte("TwoFactor")) {
			return nil, err
		}

		var twoFactor twoFactorResponse
		if err := json.Unmarshal(errsc.body, &twoFactor); err != nil {
			return nil, err
		}
		provider, token, err := twoFactorPrompt(&twoFactor)
		if err != nil {
			return nil, fmt.Errorf("could not obtain two-factor auth token: %v", err)
		}
		login.Set("twoFactorProvider", strconv.Itoa(int(provider)))
		login.Set("twoFactorToken", token)
		login.Set("twoFactorRemember", "1")
		lr = LoginResponse{}
		if err := jsonPOST(ctx, idtURL+"/connect/token", &lr, login); err != nil {
			return nil, fmt.Errorf("could not login via two-factor: %v", err)
		}
	}

	return &lr, nil
}

func chunkSplitFolders(slice []Folder, size int) [][]Folder {
	var chunks [][]Folder

	for {
		if len(slice) == 0 {
			break
		}
		if len(slice) <= size {
			size = len(slice)
		}
		chunks = append(chunks, slice[0:size])
		slice = slice[size:]
	}
	return chunks
}

func chunkSplitCiphers(slice []Cipher, size int) [][]Cipher {
	var chunks [][]Cipher

	for {
		if len(slice) == 0 {
			break
		}
		if len(slice) < size {
			size = len(slice)
		}
		chunks = append(chunks, slice[0:size])
		slice = slice[size:]
	}
	return chunks
}

func GetFolder(path string) uuid.UUID {
	var folders [][]Folder = chunkSplitFolders(globalData.Sync.Folders, CHUNKSIZE)
	var uuidchan = make(chan uuid.UUID, 1)

	var wg sync.WaitGroup
	for _, chunk := range folders {
		wg.Add(1)
		go func(mychunk []Folder, path string) {
			defer wg.Done()
			for _, item := range mychunk {
				name, err := secrets.decryptStr(item.Name)
				if err != nil {
					log.Println(err)
				}
				if err == nil && name == path {
					uuidchan <- item.ID
					break
				}
			}
		}(chunk, path)
	}
	wg.Wait()
	select {
	case id := <-uuidchan:
		return id
	default:
		break
	}
	return uuid.UUID{}
}

func Get(path string) ([]DecryptedCipher, bool) {
	var (
		entry         string = filepath.Base(path)
		folder        string = filepath.Dir(path)
		fid           uuid.UUID
		ciphers       [][]Cipher           = chunkSplitCiphers(globalData.Sync.Ciphers, CHUNKSIZE)
		decryptedchan chan DecryptedCipher = make(chan DecryptedCipher)
		decrypted     []DecryptedCipher    = make([]DecryptedCipher, 0)
	)

	if folder != "." {
		fid = GetFolder(folder)
	}

	var wg sync.WaitGroup
	for _, chunk := range ciphers {
		wg.Add(1)
		go func(mychunk []Cipher, folder, entry string, fid uuid.UUID) {
			defer wg.Done()
			for _, item := range mychunk {
				if (folder == "." && item.FolderID == nil) || (item.FolderID != nil && *item.FolderID == fid) {
					if name, err := secrets.decryptStr(item.Name); err == nil && (name == entry || entry == "*") {
						decryptedchan <- decrypt(item, name)
					}
				} else if folder == "*" {
					if name, err := secrets.decryptStr(item.Name); err == nil && (name == entry || entry == "*") {
						decryptedchan <- decrypt(item, name)
					}
				}

			}
		}(chunk, folder, entry, fid)
	}

	go func() {
		wg.Wait()
		close(decryptedchan)
	}()

	for dc := range decryptedchan {
		decrypted = append(decrypted, dc)
	}
	return decrypted, len(decrypted) > 0
}

func decrypt(c Cipher, name string) DecryptedCipher {
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
		d.Username, _ = secrets.decryptStr(c.Login.Username)
		d.Password, _ = secrets.decryptStr(c.Login.Password)
	}

	var wg sync.WaitGroup
	for _, f := range c.Fields {
		wg.Add(1)
		go func(f Field) {
			defer wg.Done()
			name, _ := secrets.decryptStr(f.Name)
			value, _ := secrets.decryptStr(f.Value)
			fieldsMutex.Lock()
			d.Fields[name] = value
			fieldsMutex.Unlock()
		}(f)
	}
	wg.Wait()
	return d
}
