package types

import "fmt"

type MissingTypeError struct {
	Value []byte
}

func (e MissingTypeError) Error() string {
	return fmt.Sprintf("cipher string does not contain a type: %q", e.Value)
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
	return fmt.Sprintf("unsupported cipher string type: %d", e.Value)
}

type InvalidMACError struct {
	Expected, Actual []byte
}

func (e InvalidMACError) Error() string {
	return fmt.Sprintf("invalid MAC: expected %q, got %q", e.Expected, e.Actual)
}
