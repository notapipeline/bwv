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
package tools

// MockProcess is a mock process for testing exec commands
type MockProcess struct {
	Status   bool
	CloseErr error
	StartErr error
	WriteErr error
	Exit     int
	Lines    []struct {
		Line []byte
		Err  error
	}
}

func (m *MockProcess) ReadLine() ([]byte, bool, error) {
	line := m.Lines[0]
	m.Lines = m.Lines[1:]
	return line.Line, m.Status, line.Err
}

func (m *MockProcess) Start(string, []string) error {
	return m.StartErr
}

func (m *MockProcess) Close() error {
	return m.CloseErr
}

func (m *MockProcess) Write([]byte) (int, error) {
	return m.Exit, m.WriteErr
}
