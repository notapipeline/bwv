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

	"r00t2.io/gokwallet"
)

var wm *gokwallet.WalletManager

// Gets a secret value from kwallet
func getSecretFromKWallet(what string) (string, error) {
	if os.Getenv("USE_LIBSECRET") != "" {
		return "", fmt.Errorf("skipping kwallet")
	}

	var err error

	if wm == nil {
		// Enumerate wallet and folder NAMES only - do not eagerly read and
		// decrypt every item in every wallet. AllWalletItems would call
		// .Update() (a D-Bus read + decrypt) on every password/map/blob in
		// every folder of every wallet at construction, which is what made
		// discovery slow. Use a fresh RecurseOpts so we don't mutate the
		// shared gokwallet.DefaultRecurseOpts.
		r := &gokwallet.RecurseOpts{Wallets: true, Folders: true}
		if wm, err = gokwallet.NewWalletManager(r, "BWVault"); err != nil {
			return "", err
		}
	}

	for _, v := range wm.Wallets {
		f, ok := v.Folders["Passwords"]
		if !ok {
			continue
		}

		// Read only the bwdata map, not the whole folder.
		m, err := gokwallet.NewMap(f, "bwdata", &gokwallet.RecurseOpts{Maps: true})
		if err != nil || m == nil {
			continue
		}

		if p, ok := m.Value[what]; ok {
			return p, nil
		}
	}
	return "", nil
}
