package aauth

import (
	"fmt"
	"strings"
)

// Requirement values used in the AAuth-Requirement header (draft -09 §12.3).
const (
	RequirementAgentToken    = "agent-token"
	RequirementAuthToken     = "auth-token"
	RequirementInteraction   = "interaction"
	RequirementClarification = "clarification"
	RequirementClaims        = "claims"
)

// HeaderRequirement is the AAuth-Requirement header name.
const HeaderRequirement = "AAuth-Requirement"

// Requirement is a parsed AAuth-Requirement header value, e.g.:
//
//	requirement=auth-token; resource-token="eyJ..."
//	requirement=interaction; url="https://ps.example/interaction"; code="A1B2-C3D4"
//	requirement=agent-token
type Requirement struct {
	Requirement string
	// ResourceToken accompanies requirement=auth-token.
	ResourceToken string
	// URL and Code accompany requirement=interaction.
	URL  string
	Code string
}

// String renders the header value.
func (r Requirement) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "requirement=%s", r.Requirement)
	if r.ResourceToken != "" {
		fmt.Fprintf(&b, "; resource-token=%q", r.ResourceToken)
	}
	if r.URL != "" {
		fmt.Fprintf(&b, "; url=%q", r.URL)
	}
	if r.Code != "" {
		fmt.Fprintf(&b, "; code=%q", r.Code)
	}
	return b.String()
}

// ParseRequirement parses an AAuth-Requirement header value. Parameters may
// be quoted or bare; unknown parameters are ignored (forward compatibility).
func ParseRequirement(v string) (Requirement, error) {
	var r Requirement
	if strings.TrimSpace(v) == "" {
		return r, fmt.Errorf("aauth: empty AAuth-Requirement value")
	}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return r, fmt.Errorf("aauth: malformed AAuth-Requirement parameter %q", part)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch key {
		case "requirement":
			r.Requirement = val
		case "resource-token":
			r.ResourceToken = val
		case "url":
			r.URL = val
		case "code":
			r.Code = val
		}
	}
	if r.Requirement == "" {
		return r, fmt.Errorf("aauth: AAuth-Requirement missing requirement parameter")
	}
	return r, nil
}
