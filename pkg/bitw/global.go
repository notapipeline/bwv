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
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/notapipeline/bwv/pkg/cache"
	"github.com/notapipeline/bwv/pkg/config"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

type Location string

type Server struct {
	ApiServer string
	IdtServer string
}

const (
	CHUNKSIZE int      = 5
	EU        Location = "eu"
	GLOBAL    Location = "com"
)

var (
	secrets *cache.SecretCache
	servers map[Location]*Server = map[Location]*Server{
		EU: {
			ApiServer: "https://api.bitwarden.eu",
			IdtServer: "https://identity.bitwarden.eu",
		},
		GLOBAL: {
			ApiServer: "https://api.bitwarden.com",
			IdtServer: "https://identity.bitwarden.com",
		},
	}
	//temporary until config is finished
	Endpoint *Server = servers[GLOBAL]
)

// SetRegion allows the regional endpoints to be set for API calls
func SetRegion(region Location) {
	Endpoint = servers[region]
}

func chunkSplitFolders(slice []types.Folder, size int) [][]types.Folder {
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

func chunkSplitCiphers(slice []types.Secret, size int) [][]types.Secret {
	var chunks [][]types.Secret

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
func GetFolder(path string) uuid.UUID {
	var folders [][]types.Folder = chunkSplitFolders(secrets.Data.Sync.Folders, CHUNKSIZE)
	var uuidchan = make(chan uuid.UUID, 1)

	var wg sync.WaitGroup
	for _, chunk := range folders {
		wg.Add(1)
		go func(mychunk []types.Folder, path string) {
			defer wg.Done()
			for _, item := range mychunk {
				name, err := secrets.DecryptStr(item.Name)
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

// Get returns a slice of DecryptedCipher objects that match the path
func Get(path string) ([]DecryptedCipher, bool) {
	var (
		entry         string = filepath.Base(path)
		folder        string = filepath.Dir(path)
		fid           uuid.UUID
		ciphers       [][]types.Secret     = chunkSplitCiphers(secrets.Data.Sync.Secrets, CHUNKSIZE)
		decryptedchan chan DecryptedCipher = make(chan DecryptedCipher)
		decrypted     []DecryptedCipher    = make([]DecryptedCipher, 0)
	)

	if folder != "." {
		fid = GetFolder(folder)
	}

	var wg sync.WaitGroup
	for _, chunk := range ciphers {
		wg.Add(1)
		go func(mychunk []types.Secret, folder, entry string, fid uuid.UUID) {
			defer wg.Done()
			for _, item := range mychunk {
				if (folder == "." && item.FolderID == nil) || (item.FolderID != nil && *item.FolderID == fid) {
					if name, err := secrets.DecryptStr(item.Name); err == nil && (name == entry || entry == "*") {
						decryptedchan <- decrypt(item, name)
					}
				} else if folder == "*" {
					if name, err := secrets.DecryptStr(item.Name); err == nil && (name == entry || entry == "*") {
						decryptedchan <- decrypt(item, name)
					}
				}

			}
		}(chunk, folder, entry, fid)
	}

	wg.Wait()
	close(decryptedchan)

	for dc := range decryptedchan {
		decrypted = append(decrypted, dc)
	}
	return decrypted, len(decrypted) > 0
}

func Sync(ctx context.Context) error {
	var data types.DataFile
	if err := transport.DefaultHttpClient.Get(ctx, Endpoint.ApiServer+"/sync", &data.Sync); err != nil {
		return fmt.Errorf("could not sync: %v", err)
	}
	if err := secrets.Update(data); err != nil {
		return fmt.Errorf("could not update secrets: %v", err)
	}
	return nil
}

func DecryptToken(token string) (string, error) {
	var (
		key, mac  []byte
		err       error
		decrypted []byte
	)

	if key, mac, err = crypto.StretchKey([]byte(cache.MasterPassword())); err != nil {
		return "", fmt.Errorf("could not stretch key: %v", err)
	}

	var t types.CipherString = types.CipherString{}
	if err = t.UnmarshalText([]byte(token)); err != nil {
		return "", fmt.Errorf("could not unmarshal token: %v", err)
	}

	if decrypted, err = crypto.DecryptWith(t, key, mac); err != nil {
		return "", fmt.Errorf("could not decrypt token: %v", err)
	}

	return config.DeriveHttpGetAPIKey(string(decrypted)), nil
}
