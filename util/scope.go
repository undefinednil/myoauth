package util

import (
	"fmt"
	"strings"
)

// supportedScopes is the set of scopes this provider implements. It mirrors
// the scopes_supported field of the discovery document: the userinfo endpoint
// only ever returns `sub` and `name`, so no other scope would grant anything.
var supportedScopes = []string{"openid", "profile"}

// AllowedScopes returns the scopes supported by the provider. The slice is a
// copy, so a caller cannot mutate the shared set.
func AllowedScopes() []string {
	out := make([]string, len(supportedScopes))
	copy(out, supportedScopes)
	return out
}

// ValidateScopes returns an error naming the first scope the provider does not
// support. Whether `openid` is required is enforced separately by the
// authorization handler; this function only checks membership so it can also
// validate the narrowing scopes of a refresh_token request.
func ValidateScopes(scopes []string) error {
	for _, scope := range scopes {
		if !isAllowedScope(strings.TrimSpace(scope)) {
			return fmt.Errorf("unsupported scope %q (supported: %s)", scope, strings.Join(supportedScopes, " "))
		}
	}
	return nil
}

func isAllowedScope(scope string) bool {
	for _, allowed := range supportedScopes {
		if scope == allowed {
			return true
		}
	}
	return false
}
