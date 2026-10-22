package variables

// SetApplyHook installs a failure-injection hook for tests in other
// packages and returns a function that removes it.
func SetApplyHook(h func(step int) error) (restore func()) {
	applyHook = h
	return func() { applyHook = nil }
}
