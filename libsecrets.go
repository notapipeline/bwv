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
	"os"

	"r00t2.io/gosecret"
)

// Gets a secret from libsecrets
func getSecretFromSecretsService(what string) (string, error) {
	if os.Getenv("USE_KWALLET") != "" {
		return "", nil
	}

	var (
		err       error
		service   *gosecret.Service
		itemAttrs map[string]string
	)

	if service, err = gosecret.NewService(); err != nil {
		return "", err
	}
	defer service.Close()

	var unlockedItems []*gosecret.Item

	itemAttrs = map[string]string{
		"Path": "/Passwords/bwdata",
	}

	service.Legacy = true
	if unlockedItems, _, err = service.SearchItems(itemAttrs); err != nil {
		return "", err
	}

	for _, item := range unlockedItems {
		attributes, _ := item.Attributes()
		for key, value := range attributes {
			if key == what {
				return value, nil
			}
		}
	}
	return "", nil
}
