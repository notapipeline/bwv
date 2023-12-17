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
package tools

import (
	"fmt"
	"os"
	"strings"

	"github.com/peterh/liner"
	"github.com/twpayne/go-pinentry"
)

// ReadPassword reads a password from the user via STDIN
func ReadPassword(prompt string) ([]byte, error) {
	line := liner.NewLiner()
	line.SetCtrlCAborts(true)
	defer line.Close()
	var (
		password string
		err      error
	)
	if password, err = line.PasswordPrompt(prompt); err != nil {
		if err == liner.ErrPromptAborted {
			line.Close()
			os.Exit(0)
		}
		return nil, err
	}
	return []byte(password), nil
}

// ReadLine reads a line of text from the user via STDIN
func ReadLine(prompt string) ([]byte, error) {
	line := liner.NewLiner()
	line.SetCtrlCAborts(true)
	defer line.Close()
	var (
		password string
		err      error
	)
	if password, err = line.Prompt(prompt); err != nil {
		if err == liner.ErrPromptAborted {
			line.Close()
			os.Exit(0)
		}
		return nil, err
	}
	return []byte(password), nil
}

// getSecret gets a secret from the environment or secrets store
func getSecret(what string) string {
	var (
		value string
		err   error
		ok    bool
	)

	if value, ok = os.LookupEnv(what); ok {
		return value
	}

	if value, err = getSecretFromKWallet(what); err == nil {
		return value
	}

	if value, err = getSecretFromSecretsService(what); err == nil {
		return value
	}
	return ""
}

// GetSecretsFromUserEnvOrStore gets secrets from the user, environment or secrets store
//
// Order is:
// 1. Environment
// 2. Secrets store
// 3. User input
func GetSecretsFromUserEnvOrStore(userInteractive bool) map[string][]byte {
	secrets := map[string][]byte{
		"BW_CLIENTID":     nil,
		"BW_CLIENTSECRET": nil,
		"BW_PASSWORD":     nil,
		"BW_EMAIL":        nil,
	}

	for k := range secrets {
		var s string = getSecret(k)
		secrets[k] = []byte(s)
		if s == "" && userInteractive {
			switch k {
			case "BW_EMAIL":
				secrets[k], _ = ReadLine(k + ": ")
			case "BW_PASSWORD":
				secrets[k], _ = GetPassword(k, "Please enter your password", "Password: ")
			}
		}
	}
	return secrets
}

// GetPassword gets a password from the user
//
// This is a mockable entry point for testing and wraps the password function.
var GetPassword func(title, description, prompt string) ([]byte, error) = password

// passwword asks the user for a password using pinentry if available and
// falls back to stdin if not.
func password(title, description, prompt string) ([]byte, error) {
	return func() ([]byte, error) {
		var (
			err         error
			client      *pinentry.Client
			password    string
			usePinentry bool = true
		)

		if client, err = GetPinentry(
			pinentry.WithBinaryNameFromGnuPGAgentConf(),
			pinentry.WithDesc(description),
			pinentry.WithGPGTTY(),
			pinentry.WithPrompt(prompt),
			pinentry.WithTitle(title),
		); err != nil {
			var b []byte
			if b, err = readPassword(prompt); err != nil {
				return nil, err
			}
			password = string(b)
			usePinentry = false
		}

		if usePinentry {
			defer client.Close()
			password, _, err = client.GetPIN()
			if pinentry.IsCancelled(err) {
				return nil, fmt.Errorf("Cancelled")
			}
		}
		if password == "" {
			return nil, fmt.Errorf("No password provided")
		}
		password = strings.TrimSpace(password)
		return []byte(password), err
	}()
}

// GetPinentry gets a pinentry client
//
// This is a mockable entry point for testing and wraps the pinentry client.
var GetPinentry func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) = func(options ...pinentry.ClientOption) (c *pinentry.Client, err error) {
	return pinentry.NewClient(options...)
}

var readPassword func(prompt string) ([]byte, error) = func(prompt string) ([]byte, error) {
	return ReadPassword(prompt)
}
