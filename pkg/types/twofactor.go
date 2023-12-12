package types

import (
	"fmt"
	"strconv"
)

type TwoFactorProvider int

func (t *TwoFactorProvider) UnmarshalText(text []byte) error {
	i, err := strconv.Atoi(string(text))
	if err != nil || i < 0 || i >= TwoFactorProviderMax {
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
