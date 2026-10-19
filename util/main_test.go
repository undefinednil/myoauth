package util

import (
	"os"
	"strings"
	"testing"
)

// TestMain scrubs every ambient MYOAUTH_* environment variable before running
// the package's tests. Without this, a variable exported in the developer's
// shell or CI job would leak into Configuration.Init and change test outcomes.
// Tests that intentionally exercise overrides use t.Setenv, which runs after
// TestMain and is restored automatically.
func TestMain(m *testing.M) {
	unsetAmbientMyOauthEnv()
	os.Exit(m.Run())
}

// unsetAmbientMyOauthEnv removes all MYOAUTH_* variables from the process
// environment.
func unsetAmbientMyOauthEnv() {
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "MYOAUTH_") {
			continue
		}
		_ = os.Unsetenv(name)
	}
}
