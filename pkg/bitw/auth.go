// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// This file is covered by the license at https://github.com/mvdan/bitw/blob/master/LICENSE
package bitw

import (
	"context"
	"encoding/base64"
	"net/url"
	"runtime"
)

type preLoginRequest struct {
	Email string `json:"email"`
}

type preLoginResponse struct {
	KDF           int
	KDFIterations int
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"key"`
}

const (
	// deviceName should probably be like "Linux", "Android", etc, but this
	// helps the human user differentiate bitw logins from those made by the
	// official clients.
	deviceName = "bitw"
	loginScope = "api offline_access"
)

func deviceType() string {
	// The enum strings come from https://github.com/bitwarden/server/blob/b19628c6f85a2cd5f1950ac222ba14840a88894d/src/Core/Enums/DeviceType.cs.
	switch runtime.GOOS {
	case "linux":
		return "8" // Linux Desktop
	case "darwin":
		return "7" // MacOS Desktop
	case "windows":
		return "6" // Windows Desktop
	default:
		return "14" // Unknown Browser, since we don't have a better fallback
	}
}

func refreshToken(ctx context.Context) error {
	return nil
}

func urlValues(pairs ...string) url.Values {
	if len(pairs)%2 != 0 {
		panic("pairs must be of even length")
	}
	vals := make(url.Values)
	for i := 0; i < len(pairs); i += 2 {
		vals.Set(pairs[i], pairs[i+1])
	}
	return vals
}

var b64enc = base64.StdEncoding.Strict()
