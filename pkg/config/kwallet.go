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
package config

import (
	"fmt"
	"os"

	"r00t2.io/gokwallet"
)

// Gets a secret value from kwallet
func getSecretFromKWallet(what string) (string, error) {
	if os.Getenv("USE_LIBSECRET") != "" {
		return "", fmt.Errorf("Skipping kwallet")
	}

	var (
		err error
		r   *gokwallet.RecurseOpts = gokwallet.DefaultRecurseOpts
		wm  *gokwallet.WalletManager
	)

	r.AllWalletItems = true
	if wm, err = gokwallet.NewWalletManager(r, "BWVault"); err != nil {
		return "", err
	}

	for _, v := range wm.Wallets {
		if f, ok := v.Folders["Passwords"]; ok {
			if m, ok := f.Maps["bwdata"]; ok {
				for k, p := range m.Value {
					if k == what {
						return p, nil
					}
				}
			}
		}
	}
	return "", nil
}
