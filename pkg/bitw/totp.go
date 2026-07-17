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
package bitw

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// totpParams are the parameters for generating a TOTP code, resolved from a
// bare base32 secret or an otpauth:// URI.
type totpParams struct {
	secret    string
	algorithm string
	digits    int
	period    int
}

// parseTotpSecret interprets a stored TOTP secret. A bare base32 secret uses the
// authenticator defaults (SHA1, 6 digits, 30s); an otpauth:// URI overrides them
// from its query parameters.
func parseTotpSecret(secret string) (totpParams, error) {
	p := totpParams{secret: secret, algorithm: "SHA1", digits: 6, period: 30}
	if !strings.HasPrefix(secret, "otpauth://") {
		return p, nil
	}

	u, err := url.Parse(secret)
	if err != nil {
		return p, fmt.Errorf("invalid otpauth uri: %w", err)
	}
	q := u.Query()
	p.secret = q.Get("secret")
	if a := q.Get("algorithm"); a != "" {
		p.algorithm = strings.ToUpper(a)
	}
	if d := q.Get("digits"); d != "" {
		if p.digits, err = strconv.Atoi(d); err != nil {
			return p, fmt.Errorf("invalid digits in otpauth uri: %w", err)
		}
	}
	if pd := q.Get("period"); pd != "" {
		if p.period, err = strconv.Atoi(pd); err != nil {
			return p, fmt.Errorf("invalid period in otpauth uri: %w", err)
		}
	}
	return p, nil
}

// hashForAlgorithm returns the hash constructor for a TOTP algorithm name.
func hashForAlgorithm(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported totp algorithm %q", algorithm)
	}
}

// totpCode generates the current TOTP code (RFC 6238 / RFC 4226) for a stored
// secret, which may be a bare base32 secret or an otpauth:// URI.
func totpCode(secret string, now time.Time) (string, error) {
	p, err := parseTotpSecret(secret)
	if err != nil {
		return "", err
	}
	if p.digits < 1 || p.digits > 8 {
		return "", fmt.Errorf("unsupported totp digit count %d", p.digits)
	}
	if p.period <= 0 {
		return "", fmt.Errorf("invalid totp period %d", p.period)
	}

	key, err := decodeBase32Secret(p.secret)
	if err != nil {
		return "", err
	}

	newHash, err := hashForAlgorithm(p.algorithm)
	if err != nil {
		return "", err
	}

	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix())/uint64(p.period))

	mac := hmac.New(newHash, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	// Dynamic truncation - RFC 4226 section 5.3.
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < p.digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", p.digits, code%mod), nil
}

// decodeBase32Secret decodes a base32 TOTP secret, tolerating lowercase, spaces
// and missing padding as commonly stored by authenticator apps.
func decodeBase32Secret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	secret = strings.TrimRight(secret, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 totp secret: %w", err)
	}
	return key, nil
}
