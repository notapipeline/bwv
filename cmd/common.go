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
package cmd

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"strings"

	"github.com/notapipeline/bwv/pkg/bitw"
	"github.com/notapipeline/bwv/pkg/crypto"
	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"

	"github.com/twpayne/go-pinentry"
)

var email string

var fatal func(format string, v ...interface{}) = func(format string, v ...interface{}) {
	if clientCmd.Debug {
		debug.PrintStack()
	}
	log.Fatalf(format, v...)
}

var createToken func() string = func() string {
	b := new(bitw.Bwv)
	return b.CreateToken()
}

var getSecretsFromUserEnvOrStore func(v bool) map[string]string = tools.GetSecretsFromUserEnvOrStore

var clientEncrypt = func(password, email, address string, kdf types.KDFInfo) (string, error) {
	return crypto.ClientEncrypt(password, email, address, kdf)
}

var getPassword func() (string, error) = func() (string, error) {
	return func() (string, error) {
		var (
			err         error
			client      *pinentry.Client
			password    string
			usePinentry bool = true
		)

		if client, err = getPinentry(
			pinentry.WithBinaryNameFromGnuPGAgentConf(),
			pinentry.WithDesc("Please enter your Bitwarden master password."),
			pinentry.WithGPGTTY(),
			pinentry.WithPrompt("Password:"),
			pinentry.WithTitle("Master password"),
		); err != nil {
			if password, err = readPassword("Please enter your Bitwarden master password: "); err != nil {
				return "", err
			}
			usePinentry = false
		}

		if usePinentry {
			defer client.Close()
			password, _, err = client.GetPIN()
			if pinentry.IsCancelled(err) {
				return "", fmt.Errorf("Cancelled")
			}
		}
		if password == "" {
			return "", fmt.Errorf("No password provided")
		}
		password = strings.TrimSpace(password)
		return password, err
	}()
}

var getPinentry func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) = func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
	return pinentry.NewClient(options...)
}

var readPassword func(prompt string) (string, error) = func(prompt string) (string, error) {
	return tools.ReadPassword(prompt)
}

func getKdf() (kdf types.KDFInfo) {
	var ctx context.Context = context.Background()
	var localAddress string = fmt.Sprintf("https://%s:%d", clientCmd.Server, clientCmd.Port)
	if err := transport.DefaultHttpClient.Get(ctx, localAddress+"/api/v1/kdf", &kdf); err != nil {
		fatal("unable to get kdf info: %q", err)
	}
	return
}

func getEncryptedToken() string {
	var (
		secrets map[string]string = getSecretsFromUserEnvOrStore(false)
		err     error
		token   string
		kdf     types.KDFInfo = getKdf()
	)

	if clientCmd.Token == "" {
		if t, ok := secrets["BW_CLIENTSECRET"]; ok {
			clientCmd.Token = t
		} else {
			clientCmd.Token = secrets["BW_PASSWORD"]
		}
	}

	if clientCmd.Token == "" {
		if err = loadClientConfig(); err != nil {
			return ""
		}
	}

	token, err = crypto.ClientEncrypt(secrets["BW_PASSWORD"], secrets["BW_EMAIL"], clientCmd.Token, kdf)
	if err != nil {
		fatal("failed to encrypt token : %q", err)
	}

	return token
}
