package config

import (
	"os"

	"github.com/notapipeline/bwv/pkg/bitw"
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

func GetSecretsFromEnvOrStore() map[string]string {
	secrets := map[string]string{
		"BW_CLIENTID":     "",
		"BW_CLIENTSECRET": "",
		"BW_PASSWORD":     "",
		"BW_EMAIL":        "",
	}

	for k := range secrets {
		var value string = os.Getenv(k)
		if value == "" {
			value = getSecret(k)
		}
		secrets[k] = value
	}
	return secrets
}

func GetFromUser() map[string]string {
	secrets := make(map[string]string)
	secrets["BW_EMAIL"], _ = bitw.ReadLine("Email: ")
	secrets["BW_PASSWORD"], _ = bitw.ReadPassword("Password: ")
	return secrets
}
