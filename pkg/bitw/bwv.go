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
	"fmt"
	"log"
	"math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

// Location identifies the servers to use for API calls
type Location string

// Server is a container for the API and Identity servers
type Server struct {
	ApiServer string
	IdtServer string
}

const (
	CHUNKSIZE int      = 5
	EU        Location = "eu"
	GLOBAL    Location = "com"
)

// Bwv coordinates the interaction between the Bitwarden API and the local
// cache.
type Bwv struct {
	Secrets  *cache.SecretCache
	Endpoint *Server

	servers  map[Location]*Server
	lr       *types.LoginResponse
	autoload *chan bool
}

// NewBwv creates a new Bwv object
func NewBwv() *Bwv {
	b := Bwv{}
	b.servers = map[Location]*Server{
		EU: {
			ApiServer: "https://api.bitwarden.eu",
			IdtServer: "https://identity.bitwarden.eu",
		},
		GLOBAL: {
			ApiServer: "https://api.bitwarden.com",
			IdtServer: "https://identity.bitwarden.com",
		},
	}

	b.SetRegion(GLOBAL)
	return &b
}

// SetAutoload sets the channel that will be used to signal that the autoloader
// should be triggered.
func (b *Bwv) SetAutoload(c *chan bool) {
	b.autoload = c
}

// SetRegion allows the regional endpoints to be set for API calls
func (b *Bwv) SetRegion(region Location) {
	b.Endpoint = b.servers[region]
}

// Get returns a slice of DecryptedCipher objects that match the path
func (b *Bwv) Get(path string) ([]DecryptedCipher, bool) {
	var (
		entry         string = filepath.Base(path)
		folder        string = filepath.Dir(path)
		fid           uuid.UUID
		ciphers       [][]types.Secret      = b.chunkSplitCiphers(b.Secrets.Data.Sync.Secrets, CHUNKSIZE)
		decryptedchan chan *DecryptedCipher = make(chan *DecryptedCipher)
		decrypted     []DecryptedCipher     = make([]DecryptedCipher, 0)
	)

	switch folder {
	case ".", "*":
	default:
		fid = b.getFolder(folder)
	}

	var wg sync.WaitGroup
	for _, chunk := range ciphers {
		wg.Add(1)
		go func(mychunk []types.Secret, folder, entry string, fid uuid.UUID) {
			defer wg.Done()
			for _, item := range mychunk {
				if (folder == "." && item.FolderID == nil) || (item.FolderID != nil && *item.FolderID == fid) {
					if name, err := b.Secrets.DecryptStr(item.Name); err == nil && (name == entry || entry == "*") {
						decryptedchan <- NewDecryptedCipher(b).Decrypt(item, name)
					}
				} else if folder == "*" {
					if name, err := b.Secrets.DecryptStr(item.Name); err == nil && (name == entry || entry == "*") {
						decryptedchan <- NewDecryptedCipher(b).Decrypt(item, name)
					}
				}

			}
		}(chunk, folder, entry, fid)
	}

	go func() {
		wg.Wait()
		log.Println("Closing decryption channel")
		close(decryptedchan)
	}()

	for dc := range decryptedchan {
		decrypted = append(decrypted, *dc)
	}
	log.Println("Found", len(decrypted), "items")
	return decrypted, len(decrypted) > 0
}

// CreateToken generates a random string that can be used as a bearer token
// for operations passed from clients connecting remotely. These tokens are not
// used for clients running on the same host as the server as these are expected
// to use either the Bitwarden API key or the user's master password.
//
// When running onm the same host as the server, the should be expected to
// retrieve variables from either libsecret or kwallet, or from the environment.
func (b *Bwv) CreateToken() string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	r := make([]rune, 32)
	for i := range r {
		r[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(r)
}

// Decrypt the token sent as Bearer in the Authorization header
func (b *Bwv) DecryptToken(token string) (string, error) {
	var t types.CipherString = types.CipherString{}
	if err := t.UnmarshalText([]byte(token)); err != nil {
		return "", fmt.Errorf("could not unmarshal token: %v", err)
	}

	return b.Secrets.DecryptStr(t)
}

// Sync the local cache with the server
func (b *Bwv) Sync() (err error) {
	data := &types.DataFile{
		LoginResponse: b.lr,
		DeviceID:      "bwv",
		KDF:           b.lr.KDFInfo,
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, transport.AuthToken{}, b.lr.AccessToken)

	if err = transport.DefaultHttpClient.Get(ctx, b.Endpoint.ApiServer+"/sync", &data.Sync); err != nil {
		err = fmt.Errorf("could not sync: %w", err)
		return
	}

	data.LastSync = time.Now()
	if err = b.Secrets.Update(data); err != nil {
		err = fmt.Errorf("could not update secrets: %w", err)
		return
	}

	log.Println("Sync complete")
	return
}

// salt is used to salt the master password when encrypting the hashed password
// for storage in the secret cache.
func (b *Bwv) salt() string {
	return fmt.Sprintf("__PROTECTED__%s%s", b.Secrets.Data.Sync.Profile.ID, types.UserAutoKey)
}

// Setup the Bitwarden client
func (b *Bwv) Setup() *Bwv {
	var (
		err        error
		secrets    map[string]string = config.GetSecrets(true)
		hashed     string
		useApiKeys bool = secrets["BW_CLIENTID"] != "" && secrets["BW_CLIENTSECRET"] != ""
	)

	if useApiKeys {
		log.Println("Setting up Bitwarden client using API key login")
		if b.lr, err = b.ApiLogin(secrets); err != nil {
			log.Fatal(err)
		}
	} else {
		if hashed, err = b.prelogin(secrets["BW_PASSWORD"], secrets["BW_EMAIL"]); err != nil {
			log.Fatal(err)
		}

		if b.lr, err = b.UserLogin(hashed, secrets["BW_EMAIL"]); err != nil {
			log.Fatal(err)
		}
	}

	var (
		active chan bool = make(chan bool)
		done   chan bool = make(chan bool)
	)
	go b.refresh(active, done, true)
	active <- true

	// Wait for the first sync to complete before continuing
	// This allows the secret cache to be populated before
	// we try to store the user session when using UserAuth login
	<-done

	if len(hashed) > 0 {
		// The hashed password needs to be stored for re-authentication when the
		// auth token expires. As we don't want to keep asking the user to enter
		// their master password, we encrypt the hashed password with a key
		// derived from the master password salted with a string that is unique
		// to the user and the application.
		var salt = b.salt()
		var key, mac []byte
		key, mac, err = crypto.DeriveStretchedMasterKey(cache.MasterPassword(), salt, b.lr.KDFInfo)
		if err != nil {
			log.Fatal(err)
		}

		b.Secrets.Data.Session, err = crypto.EncryptWith([]byte(hashed), types.AesCbc256_HmacSha256_B64, key, mac)
		if err != nil {
			log.Fatal(err)
		}
	}

	return b
}

// refresh the token when it expires
//
// This is run as a go routine and shouldn't be called directly by any other
// function than the Setup() function.
//
// The active channel is used to signal that the token should be refreshed
// immediately and when triggered, will re-authenticate to the Bitwarden server
// to update the Access token and sync the local cache.
func (b *Bwv) refresh(active, done chan bool, firstRun bool) {
	for {
		select {
		// Refresh the token 5 seconds before it expires to give the client
		// enough time to complete the sync.
		case <-time.After(time.Duration(b.lr.ExpiresIn-5) * time.Second):
			go func() { active <- true }()
		case <-active:
			if b.Secrets.Data != nil {
				var apiLogin bool = b.Secrets.Data.Session.IsZero()
				if apiLogin {
					log.Println("Refreshing API token...")
					if b.lr, _ = b.ApiLogin(config.GetSecrets(true)); b.lr == nil {
						log.Println("Could not refresh API token")
						continue
					}
				} else {
					log.Println("Refreshing user token...")
					var (
						salt   = b.salt()
						k, m   []byte
						hashed []byte
						err    error
						kdf    = b.lr.KDFInfo
					)
					k, m, _ = crypto.DeriveStretchedMasterKey(cache.MasterPassword(), salt, kdf)
					if hashed, err = crypto.DecryptWith(b.Secrets.Data.Session, k, m); err != nil {
						log.Println("Could not decrypt session token", err)
						continue
					}

					var email string = b.Secrets.Data.Sync.Profile.Email
					if b.lr, err = b.UserLogin(string(hashed), email); err != nil {
						log.Println("Could not refresh user token", err)
						continue
					}
				}
			}
			log.Println("Syncing...")
			if err := b.Sync(); err != nil {
				log.Println(err)
			}

			// We need to force the calling method to wait until the first sync
			// has completed before it is allowed to return.
			if firstRun {
				firstRun = false
				done <- true
			}

			// Call the autoloader if it has been set
			if b.autoload != nil {
				*b.autoload <- true
			}
		}
	}
}

// chunkSplitFolders splits the number of folders contained in the vault into
// smaller chunks to allow for parallel processing.
func (b *Bwv) chunkSplitFolders(slice []types.Folder, size int) [][]types.Folder {
	var chunks [][]types.Folder

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

// chunkSplitCiphers splits the number of ciphers contained in the vault into
// smaller chunks to allow for parallel processing.
func (b *Bwv) chunkSplitCiphers(slice []types.Secret, size int) [][]types.Secret {
	var chunks [][]types.Secret

	log.Println("Splitting", len(slice), "ciphers into chunks of", size)
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

// GetFolder returns the uuid of the folder that matches the path
func (b *Bwv) getFolder(path string) uuid.UUID {
	var folders [][]types.Folder = b.chunkSplitFolders(b.Secrets.Data.Sync.Folders, CHUNKSIZE)
	var uuidchan = make(chan uuid.UUID, 1)

	var wg sync.WaitGroup
	for _, chunk := range folders {
		wg.Add(1)
		go func(mychunk []types.Folder, path string) {
			defer wg.Done()
			for _, item := range mychunk {
				name, err := b.Secrets.DecryptStr(item.Name)
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
