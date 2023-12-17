// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// This file is covered by the license at https://github.com/mvdan/bitw/blob/master/LICENSE
package bitw

import (
	"fmt"
	"os"
	"strconv"

	"github.com/notapipeline/bwv/pkg/tools"
	"github.com/notapipeline/bwv/pkg/transport"
	"github.com/notapipeline/bwv/pkg/types"
)

func twoFactorPrompt(resp *transport.TwoFactorRequiredError) (types.TwoFactorProvider, string, error) {
	var selected types.TwoFactorProvider
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
		var available []types.TwoFactorProvider
		for pv := types.TwoFactorProvider(0); pv < types.TwoFactorProviderMax; pv++ {
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
		i, err := strconv.Atoi(string(input))
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
	return selected, string(token), nil
}
