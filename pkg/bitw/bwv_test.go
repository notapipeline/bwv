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
package bitw

import (
	"testing"

	"github.com/google/uuid"
	"github.com/notapipeline/bwv/pkg/types"
)

// TestGetFolderIgnoresTrailingSeparator covers a folder saved in Bitwarden as
// "choclab/customers/". Bitwarden accepts the trailing slash and nests the
// folder exactly as it would without it, so a request for
// "choclab/customers/giantswarm" must still resolve.
func TestGetFolderIgnoresTrailingSeparator(t *testing.T) {
	tests := []struct {
		name   string
		folder string
		path   string
		want   string
	}{
		{"exact match", "choclab/customers", "choclab/customers/giantswarm", "giantswarm"},
		{"trailing separator on the folder", "choclab/customers/", "choclab/customers/giantswarm", "giantswarm"},
		{"trailing separator on the request", "choclab/customers", "choclab/customers//giantswarm", "giantswarm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBwv(t)

			fid := uuid.MustParse("1a89853a-5e21-4a89-9245-b4b60161865f")
			b.Secrets.Data = &types.DataFile{
				Sync: types.SyncData{
					Folders: []types.Folder{{ID: fid, Name: encrypt(t, b, tt.folder)}},
					Secrets: []types.Secret{{
						Type:     types.CipherIdentity,
						ID:       uuid.MustParse("55555555-5555-5555-5555-555555555555"),
						Name:     encrypt(t, b, "giantswarm"),
						FolderID: &fid,
						Identity: &types.Identity{Company: encrypt(t, b, "Giant Swarm")},
					}},
				},
			}

			ciphers, ok := b.Get(tt.path)
			if !ok {
				t.Fatalf("Get(%q) found nothing", tt.path)
			}
			if len(ciphers) != 1 || ciphers[0].Name != tt.want {
				t.Fatalf("Get(%q) = %+v, want one cipher named %q", tt.path, ciphers, tt.want)
			}
			if got := ciphers[0].Get("company"); got != "Giant Swarm" {
				t.Errorf("company = %v, want %q", got, "Giant Swarm")
			}
		})
	}
}
