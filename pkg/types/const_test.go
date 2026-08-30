/*
 *   Copyright 2025 Martin Proffitt <mproffitt@choclab.net>
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
package types

import "testing"

// The cipher type is wire data: Bitwarden sends the number and we filter on it,
// so these must match libs/common/src/vault/enums/cipher-type.ts exactly.
func TestCipherTypesMatchBitwarden(t *testing.T) {
	tests := []struct {
		name string
		got  SecretType
		want int
	}{
		{"Login", CipherLogin, 1},
		{"SecureNote", CipherNote, 2},
		{"Card", CipherCard, 3},
		{"Identity", CipherIdentity, 4},
		{"SshKey", CipherSshKey, 5},
		{"BankAccount", CipherBankAccount, 6},
		{"DriversLicense", CipherDriversLicense, 7},
		{"Passport", CipherPassport, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.got) != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}
