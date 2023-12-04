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
package cmd

type MockProcess struct {
	value               string
	status              bool
	readlnerr, closeerr error
	starterr, writeerr  error
	exit                int
	lines               []struct {
		line []byte
		err  error
	}
}

func (m *MockProcess) ReadLine() ([]byte, bool, error) {
	line := m.lines[0]
	m.lines = m.lines[1:]
	return line.line, m.status, line.err
}

func (m *MockProcess) Start(string, []string) error {
	return m.starterr
}

func (m *MockProcess) Close() error {
	return m.closeerr
}

func (m *MockProcess) Write([]byte) (int, error) {
	return m.exit, m.writeerr
}
