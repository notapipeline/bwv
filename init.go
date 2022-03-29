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
package main

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/notapipeline/bwv/pkg/bitw"
)

const DURATION = 15

var syncComplete chan bool = make(chan bool)

func getSecret(what string) string {
	var (
		value string
		err   error
	)
	if value, err = getSecretFromKWallet(what); err == nil {
		return value
	}

	if value, err = getSecretFromSecretsService(what); err == nil {
		return value
	}
	return ""
}

func getSecretsFromEnvOrStore() map[string]string {
	secrets := map[string]string{
		"BW_CLIENTID":     "",
		"BW_CLIENTSECRET": "",
		"BW_PASSWORD":     "",
		"BW_EMAIL":        "",
	}

	for k := range secrets {
		var value string = os.Getenv(k)
		if value == "" {
			value = getSecret(k)
		}
		secrets[k] = value
	}
	return secrets
}

func getFromUser() map[string]string {
	secrets := make(map[string]string)
	secrets["BW_EMAIL"], _ = bitw.ReadLine("Email: ")
	secrets["BW_PASSWORD"], _ = bitw.ReadPassword("Password: ")
	return secrets
}

func contains(what string, where []string) bool {
	for _, item := range where {
		if what == item {
			return true
		}
	}
	return false
}

func init() {
	initCommands := []string{"serve", "genkey", "revoke"}
	if !contains(os.Args[1], initCommands) {
		return
	}

	// Disable log datestamps if we're running as a systemd service
	if os.Getenv("NO_DATELOG") == "true" {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	secrets := getSecretsFromEnvOrStore()

	var (
		loginResponse *bitw.LoginResponse
		useApiKeys    bool = secrets["BW_CLIENTID"] != "" && secrets["BW_CLIENTSECRET"] != ""
	)

	for {
		if secrets["BW_PASSWORD"] == "" || secrets["BW_EMAIL"] == "" {
			s := getFromUser()
			for k, v := range s {
				secrets[k] = v
			}
		}

		var (
			wg      sync.WaitGroup
			success bool        = false
			pwchan  chan string = make(chan string, 1)
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := bitw.Prelogin(secrets["BW_EMAIL"])
			if err != nil {
				log.Fatal(err)
			}
			hashed := bitw.SetMasterPassword(secrets["BW_PASSWORD"], secrets["BW_EMAIL"], p)
			// for user logins we require the hashed password. For api logins, we don't.
			// this means for user logins we're forced to wait for the pre-login phase
			// to complete and the master password to be configured.
			if !useApiKeys {
				pwchan <- hashed
			}
			log.Println("Master password configured")
		}()

		wg.Add(1)
		go func() {
			var err error
			defer wg.Done()
			if useApiKeys {
				if loginResponse, err = bitw.ApiLogin(secrets["BW_CLIENTID"], secrets["BW_CLIENTSECRET"]); err != nil {
					log.Fatalf("Error : Failed to retrieve auth token : %s\n", err)
					return
				}
			} else {
				hashedpw := <-pwchan
				if loginResponse, err = bitw.UserLogin(hashedpw, secrets["BW_EMAIL"]); err != nil {
					log.Fatalf("Error : Failed to retrieve auth token : %s\n", err)
					return
				}
			}
			success = true
			log.Println("Login complete")
		}()
		wg.Wait()

		if success {
			break
		}
	}

	// force sync every DURATION minutes
	go func() {
		tick := time.Tick(DURATION * time.Second)
		for {
			syncStore(loginResponse)
			<-tick
		}
	}()
}

func syncStore(loginResponse *bitw.LoginResponse) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, bitw.AuthToken{}, loginResponse.AccessToken)
	if err := bitw.Sync(ctx); err != nil {
		log.Fatal(err)
	}
	syncComplete <- true
	log.Println("Sync complete")
}
