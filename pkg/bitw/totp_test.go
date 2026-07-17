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
	"encoding/base32"
	"fmt"
	"testing"
	"time"
)

// RFC 6238 Appendix B seeds, base32-encoded (no padding) for the secret param.
func b32(seed string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(seed))
}

var (
	sha1Seed   = "12345678901234567890"
	sha256Seed = "12345678901234567890123456789012"
	sha512Seed = "1234567890123456789012345678901234567890123456789012345678901234"
)

func TestTotpCode(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		unix   int64
		want   string
	}{
		// A bare base32 secret uses the default 6 digits: the last 6 of the
		// RFC's 8-digit T=59 SHA1 vector (94287082).
		{"bare secret default 6 digits", b32(sha1Seed), 59, "287082"},

		// RFC 6238 Appendix B, 8-digit vectors.
		{"sha1 t=59", fmt.Sprintf("otpauth://totp/x?secret=%s&algorithm=SHA1&digits=8", b32(sha1Seed)), 59, "94287082"},
		{"sha1 t=1111111109", fmt.Sprintf("otpauth://totp/x?secret=%s&digits=8", b32(sha1Seed)), 1111111109, "07081804"},
		{"sha1 t=1234567890", fmt.Sprintf("otpauth://totp/x?secret=%s&digits=8", b32(sha1Seed)), 1234567890, "89005924"},
		{"sha256 t=59", fmt.Sprintf("otpauth://totp/x?secret=%s&algorithm=SHA256&digits=8", b32(sha256Seed)), 59, "46119246"},
		{"sha512 t=59", fmt.Sprintf("otpauth://totp/x?secret=%s&algorithm=SHA512&digits=8", b32(sha512Seed)), 59, "90693936"},

		// Case/space tolerance in a bare secret.
		{"lowercase spaced secret", "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 59, "287082"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := totpCode(tt.secret, time.Unix(tt.unix, 0))
			if err != nil {
				t.Fatalf("totpCode() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("totpCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTotpCodeErrors(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{"invalid base32", "not!base32!"},
		{"unsupported algorithm", fmt.Sprintf("otpauth://totp/x?secret=%s&algorithm=MD5", b32(sha1Seed))},
		{"bad digits", fmt.Sprintf("otpauth://totp/x?secret=%s&digits=99", b32(sha1Seed))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := totpCode(tt.secret, time.Unix(59, 0)); err == nil {
				t.Errorf("totpCode(%q) expected error, got nil", tt.secret)
			}
		})
	}
}
