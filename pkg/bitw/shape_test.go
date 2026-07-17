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
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestShapeResponse(t *testing.T) {
	id1 := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	id2 := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	c1 := DecryptedCipher{ID: id1, Username: "user1", Fields: map[string]string{"example": "v1"}}
	c2 := DecryptedCipher{ID: id2, Username: "user2", Fields: map[string]string{"example": "v2"}}

	s := &HttpServer{}

	t.Run("nothing requested returns the ciphers slice", func(t *testing.T) {
		got := s.shapeResponse([]DecryptedCipher{c1}, map[string][]string{})
		if _, ok := got.([]DecryptedCipher); !ok {
			t.Fatalf("expected []DecryptedCipher, got %T", got)
		}
	})

	t.Run("single cipher single value collapses to value", func(t *testing.T) {
		got := s.shapeResponse([]DecryptedCipher{c1}, map[string][]string{"fields": {"example"}})
		want := map[string]interface{}{"value": "v1"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("single cipher multiple values returns flat map", func(t *testing.T) {
		got := s.shapeResponse([]DecryptedCipher{c1}, map[string][]string{"fields": {"example"}, "properties": {"username"}})
		want := map[string]interface{}{"example": "v1", "username": "user1"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("multiple ciphers key by id and drop nothing", func(t *testing.T) {
		got := s.shapeResponse([]DecryptedCipher{c1, c2}, map[string][]string{"fields": {"example"}})
		want := map[string]interface{}{
			id1.String(): map[string]interface{}{"value": "v1"},
			id2.String(): map[string]interface{}{"value": "v2"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})
}

func TestChunk(t *testing.T) {
	tests := []struct {
		name string
		in   []int
		size int
		want [][]int
	}{
		{"empty", nil, 2, nil},
		{"smaller than size", []int{1, 2}, 5, [][]int{{1, 2}}},
		{"exact multiple", []int{1, 2, 3, 4}, 2, [][]int{{1, 2}, {3, 4}}},
		{"remainder", []int{1, 2, 3, 4, 5}, 2, [][]int{{1, 2}, {3, 4}, {5}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chunk(tt.in, tt.size); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("chunk(%v, %d) = %v, want %v", tt.in, tt.size, got, tt.want)
			}
		})
	}
}
