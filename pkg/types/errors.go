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
package types

import (
	"fmt"
)

type MissingTypeError struct {
	Value []byte
}

func (e MissingTypeError) Error() string {
	return fmt.Sprintf("cipher string does not contain type: %q", e.Value)
}

type InvalidTypeError struct {
	Value []byte
}

func (e InvalidTypeError) Error() string {
	return fmt.Sprintf("invalid cipher string type: %q", e.Value)
}

type UnsupportedTypeError struct {
	Value int
}

func (e UnsupportedTypeError) Error() string {
	return fmt.Sprintf("unsupported cipher string type or key length: %d", e.Value)
}

type InvalidKeyLengthError struct {
	Value int
	Type  CipherStringType
}

func (e InvalidKeyLengthError) Error() string {
	return fmt.Sprintf("invalid key length: %d for key type %s", e.Value, e.Type.String())
}

type InvalidMACError struct {
	Expected, Actual []byte
}

func (e InvalidMACError) Error() string {
	return fmt.Sprintf("invalid MAC: expected %q, got %q", e.Expected, e.Actual)
}

type SyncFailedError struct {
	Err error
}

func (e SyncFailedError) Error() string {
	return fmt.Sprintf("sync failed: %s", e.Err.Error())
}
