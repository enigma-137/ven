// Package domain holds small helpers shared by the application services:
// validation errors and slug generation.
package domain

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/enigma-137/ven/internal/storage"
)

// Re-exported storage sentinels so callers need not import storage.
var (
	ErrNotFound = storage.ErrNotFound
	ErrConflict = storage.ErrConflict
)

// ValidationError reports invalid user input. Messages never contain values.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return e.Field + ": " + e.Message
}

// Invalid builds a ValidationError.
func Invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}

// IsValidation reports whether err is a ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

// Slugify lowercases s and replaces runs of non-alphanumeric characters with '-'.
func Slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if len(out) > 64 {
		out = strings.TrimRight(out[:64], "-")
	}
	return out
}

// CleanName trims and validates a display name.
func CleanName(field, name string, max int) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", Invalid(field, "is required")
	}
	if !utf8.ValidString(name) {
		return "", Invalid(field, "must be valid UTF-8")
	}
	if utf8.RuneCountInString(name) > max {
		return "", Invalid(field, "must be at most %d characters", max)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", Invalid(field, "must not contain control characters")
		}
	}
	if Slugify(name) == "" {
		return "", Invalid(field, "must contain at least one letter or digit")
	}
	return name, nil
}

// CleanDescription trims and validates an optional description.
func CleanDescription(desc string) (string, error) {
	desc = strings.TrimSpace(desc)
	if !utf8.ValidString(desc) {
		return "", Invalid("description", "must be valid UTF-8")
	}
	if len(desc) > 500 {
		return "", Invalid("description", "must be at most 500 bytes")
	}
	if strings.ContainsRune(desc, 0) {
		return "", Invalid("description", "must not contain NUL bytes")
	}
	return desc, nil
}
