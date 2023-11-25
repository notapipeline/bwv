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
