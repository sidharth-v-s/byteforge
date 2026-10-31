// Package bferrors defines the error taxonomy used across ByteForge.
//
// Every user-facing failure is classified so the CLI can return a stable
// exit code. The classification is deliberately small: processing failures,
// usage failures, I/O failures, and verification/authentication failures.
package bferrors

import (
	"errors"
	"fmt"
)

// Kind classifies an error for exit-code mapping.
type Kind int

const (
	// Processing means the operation failed while transforming data.
	Processing Kind = iota
	// Usage means the request was invalid or unsupported.
	Usage
	// IO means a filesystem or stream operation failed.
	IO
	// Verification means a round-trip check or authentication check failed.
	Verification
)

// Error is a classified ByteForge error.
type Error struct {
	Kind    Kind
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Message
	}
	if e.Message == "" {
		return e.Err.Error()
	}
	return e.Message + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// New builds a classified error.
func New(kind Kind, format string, args ...any) error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Wrap attaches context to an error if it is non-nil.
func Wrap(kind Kind, err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...), Err: err}
}

// KindOf returns the classification of err, defaulting to Processing.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Processing
}

// ExitCode maps an error to the documented process exit code.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	switch KindOf(err) {
	case Usage:
		return 2
	case IO:
		return 3
	case Verification:
		return 4
	default:
		return 1
	}
}
