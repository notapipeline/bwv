// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// This file is covered by the license at https://github.com/mvdan/bitw/blob/master/LICENSE
package bitw

import (
	"fmt"
	"os"
	"strconv"

	"github.com/notapipeline/bwv/pkg/tools"
)

type TwoFactorProvider int

// Enum values copied from https://github.com/bitwarden/server/blob/f311f40d9333442a727eb8b77f3859597de199da/src/Core/Enums/TwoFactorProviderType.cs.
// Do not use iota, to clarify that these integer values are defined elsewhere.
const (
	Authenticator         TwoFactorProvider = 0
	Email                 TwoFactorProvider = 1
	Duo                   TwoFactorProvider = 2
	YubiKey               TwoFactorProvider = 3
	U2f                   TwoFactorProvider = 4
	Remember              TwoFactorProvider = 5
	OrganizationDuo       TwoFactorProvider = 6
	_TwoFactorProviderMax                   = 7
)

func (t *TwoFactorProvider) UnmarshalText(text []byte) error {
	i, err := strconv.Atoi(string(text))
	if err != nil || i < 0 || i >= _TwoFactorProviderMax {
		return fmt.Errorf("invalid two-factor auth provider: %q", text)
	}
	*t = TwoFactorProvider(i)
	return nil
}

func (t TwoFactorProvider) Line(extra map[string]interface{}) string {
	switch t {
	case Authenticator:
		return "Six-digit authenticator token: "
	case Email:
		emailHint := extra["Email"].(string)
		return fmt.Sprintf("Six-digit email token (%s): ", emailHint)
	}
	return fmt.Sprintf("unsupported two factor auth provider %d", t)
}

type twoFactorResponse struct {
	TwoFactorProviders2 map[TwoFactorProvider]map[string]interface{}
}

func twoFactorPrompt(resp *twoFactorResponse) (TwoFactorProvider, string, error) {
	var selected TwoFactorProvider
	switch len(resp.TwoFactorProviders2) {
	case 0:
		return -1, "", fmt.Errorf("API requested 2fa but has no available providers")
	case 1:
		// Use the single available provider.
		for provider := range resp.TwoFactorProviders2 {
			selected = provider
			break
		}
	default:
		// List all available providers, and make the user choose.
		// Don't range over the map directly, as the order wouldn't be stable.
		var available []TwoFactorProvider
		for pv := TwoFactorProvider(0); pv < _TwoFactorProviderMax; pv++ {
			extra, ok := resp.TwoFactorProviders2[pv]
			if !ok {
				continue
			}
			available = append(available, pv)
			fmt.Fprintf(os.Stderr, "%d) %s\n", len(available), pv.Line(extra))
		}
		input, err := tools.ReadLine(fmt.Sprintf("Select a two-factor auth provider [1-%d]", len(available)))
		if err != nil {
			return -1, "", err
		}
		i, err := strconv.Atoi(input)
		if err != nil {
			return -1, "", err
		}
		if i <= 0 || i > len(available) {
			return -1, "", fmt.Errorf("selected option %d is not within the range [1-%d]", i, len(available))
		}
		selected = available[i-1]
	}
	token, err := tools.ReadLine(selected.Line(resp.TwoFactorProviders2[selected]))
	if err != nil {
		return -1, "", err
	}
	return selected, token, nil
}
