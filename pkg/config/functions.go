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
package config

import (
	"os"
)

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

func GetSecretsFromUserEnvOrStore() map[string]string {
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

		switch k {
		case "BW_PASSWORD", "BW_EMAIL":
			if value == "" {
				//value = readline
			}
		}
		secrets[k] = value
	}
	return secrets
}

/*func GetFromUser() map[string]string {
	secrets := make(map[string]string)
	secrets["BW_EMAIL"], _ = bitw.ReadLine("Email: ")
	secrets["BW_PASSWORD"], _ = bitw.ReadPassword("Password: ")
	return secrets
}*/
