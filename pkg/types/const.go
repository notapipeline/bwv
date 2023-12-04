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
package types

// Taken from https://github.com/bitwarden/jslib/blob/f30d6f8027055507abfdefd1eeb5d9aab25cc601/src/enums/encryptionType.ts
const (
	AesCbc256_B64                     CipherStringType = 0
	AesCbc128_HmacSha256_B64          CipherStringType = 1
	AesCbc256_HmacSha256_B64          CipherStringType = 2
	Rsa2048_OaepSha256_B64            CipherStringType = 3
	Rsa2048_OaepSha1_B64              CipherStringType = 4
	Rsa2048_OaepSha256_HmacSha256_B64 CipherStringType = 5
	Rsa2048_OaepSha1_HmacSha256_B64   CipherStringType = 6
	KDFTypePBKDF2                     KDFType          = 0
	KDFTypeArgon2id                   KDFType          = 1
)

const (
	_ SecretType = iota
	CipherLogin
	CipherCard
	CipherIdentity
	CipherNote
)

const (
	SEPARATOR   = "|"
	WITH_MAC    = 3
	WITHOUT_MAC = 2
)

const (
	Authenticator        TwoFactorProvider = 0
	Email                TwoFactorProvider = 1
	Duo                  TwoFactorProvider = 2
	YubiKey              TwoFactorProvider = 3
	U2f                  TwoFactorProvider = 4
	Remember             TwoFactorProvider = 5
	OrganizationDuo      TwoFactorProvider = 6
	TwoFactorProviderMax                   = 7
)
