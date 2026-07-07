package aauth

import (
	"fmt"
	"strings"
)

// AgentIdentifier is the parsed form of an AAuth agent identifier:
//
//	aauth:<name>@<domain>                    — a top-level agent
//	aauth:<name>+<discriminator>@<domain>    — a sub-agent (draft -09 §10.2)
//
// The identifier is stable across key rotations (it is the token's sub);
// keys are conveyed separately via cnf.jwk.
type AgentIdentifier struct {
	Name          string // the agent name
	Discriminator string // sub-agent discriminator; non-empty marks a sub-agent
	Domain        string // the agent's domain
}

// ParseAgentIdentifier parses an "aauth:" identifier string.
func ParseAgentIdentifier(s string) (AgentIdentifier, error) {
	var id AgentIdentifier
	rest, ok := strings.CutPrefix(s, "aauth:")
	if !ok {
		return id, fmt.Errorf("aauth: identifier %q missing aauth: prefix", s)
	}
	local, domain, ok := strings.Cut(rest, "@")
	if !ok || local == "" || domain == "" {
		return id, fmt.Errorf("aauth: identifier %q not in aauth:name@domain form", s)
	}
	name, disc, _ := strings.Cut(local, "+")
	if name == "" {
		return id, fmt.Errorf("aauth: identifier %q has empty name", s)
	}
	return AgentIdentifier{Name: name, Discriminator: disc, Domain: domain}, nil
}

// String renders the canonical identifier form.
func (a AgentIdentifier) String() string {
	if a.Discriminator != "" {
		return fmt.Sprintf("aauth:%s+%s@%s", a.Name, a.Discriminator, a.Domain)
	}
	return fmt.Sprintf("aauth:%s@%s", a.Name, a.Domain)
}

// IsSubAgent reports whether the identifier carries a sub-agent discriminator.
func (a AgentIdentifier) IsSubAgent() bool { return a.Discriminator != "" }

// SubAgent derives a sub-agent identifier under this agent (draft -09 §10.2:
// single level only — deriving from a sub-agent is an error).
func (a AgentIdentifier) SubAgent(discriminator string) (AgentIdentifier, error) {
	if a.IsSubAgent() {
		return AgentIdentifier{}, fmt.Errorf("aauth: %s is already a sub-agent (single-level rule)", a)
	}
	if discriminator == "" || strings.ContainsAny(discriminator, "+@") {
		return AgentIdentifier{}, fmt.Errorf("aauth: invalid sub-agent discriminator %q", discriminator)
	}
	return AgentIdentifier{Name: a.Name, Discriminator: discriminator, Domain: a.Domain}, nil
}

// Parent returns the parent identifier of a sub-agent.
func (a AgentIdentifier) Parent() (AgentIdentifier, error) {
	if !a.IsSubAgent() {
		return AgentIdentifier{}, fmt.Errorf("aauth: %s is not a sub-agent", a)
	}
	return AgentIdentifier{Name: a.Name, Domain: a.Domain}, nil
}
