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
	"os"

	"github.com/peterh/liner"
)

func ReadPassword(prompt string) (string, error) {
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
		return "", err
	}
	return password, nil
}

func ReadLine(prompt string) (string, error) {
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
		return "", err
	}
	return password, nil
}

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

// GetSecretsFromUserEnvOrStore gets secrets from the user, environment or secrets store
//
// Order is:
// 1. Environment
// 2. Secrets store
// 3. User input
func GetSecretsFromUserEnvOrStore(userInteractive bool) map[string]string {
	secrets := map[string]string{
		"BW_CLIENTID":     "",
		"BW_CLIENTSECRET": "",
		"BW_PASSWORD":     "",
		"BW_EMAIL":        "",
	}

	for k := range secrets {
		// Default comes from environment
		var value string = os.Getenv(k)
		if value == "" {
			// If not in environment, try to get from secrets store
			value = getSecret(k)
		}

		if value == "" && userInteractive {
			switch k {
			case "BW_PASSWORD", "BW_EMAIL":
				value, _ = ReadLine(k + ": ")
			}
		}
		secrets[k] = value
	}
	return secrets
}

// GetFromUser gets secrets from the user [deprecated]
//
// In this instance, only the email and password are required
// as this method will be used for MFA authentication and not
// for API authentication.
func GetFromUser() map[string]string {
	secrets := make(map[string]string)
	secrets["BW_EMAIL"], _ = ReadLine("Email: ")
	secrets["BW_PASSWORD"], _ = ReadPassword("Password: ")
	return secrets
}
