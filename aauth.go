// Package aauth implements the AAuth protocol
// (draft-hardt-oauth-aauth-protocol-09) — agent identity and authorization
// across trust domains: agent tokens, the RFC 9421 HTTP message-signature
// profile with Signature-Key key distribution
// (draft-hardt-httpbis-signature-key-04), Person Server permission requests,
// and the deferred-response (202) state machine.
//
// It targets the self-hosted / local-agent deployment shape first (the agent
// is its own agent provider per draft-hardt-aauth-bootstrap-01 §4.3), because
// that is what autonomous coding agents on developer machines are. Hosted
// agent-provider flows verify with the same primitives via JWKS discovery.
//
// This is, to our knowledge, the first Go implementation of the protocol.
// Wire conformance is pinned by golden vectors under testdata/.
package aauth

import "errors"

// JWT typ header values (draft -09 §5.2.2, §6, §7).
const (
	TypAgent    = "aa-agent+jwt"
	TypResource = "aa-resource+jwt"
	TypAuth     = "aa-auth+jwt"
)

// Well-known metadata document names (draft -09 §4; used as the dwk claim
// and as /.well-known/{name} paths).
const (
	WellKnownAgent    = "aauth-agent.json"
	WellKnownPerson   = "aauth-person.json"
	WellKnownResource = "aauth-resource.json"
	WellKnownAccess   = "aauth-access.json"
)

// HTTP header names.
const (
	HeaderSignatureKey   = "Signature-Key"
	HeaderSignatureInput = "Signature-Input"
	HeaderSignature      = "Signature"
	HeaderSignatureError = "Signature-Error"
	HeaderPrefer         = "Prefer"
	HeaderRetryAfter     = "Retry-After"
	HeaderLocation       = "Location"
)

// DefaultSignatureLabel is the signature label used by this implementation.
// Draft examples use "sig"; RFC 9421 labels are correlated by equality
// across Signature-Input, Signature, and Signature-Key (signature-key §3).
const DefaultSignatureLabel = "sig"

// Recommended lifetimes (draft -09 §5.2.2: agent tokens SHOULD NOT exceed 24h).
const (
	MaxAgentTokenTTLSeconds = 24 * 60 * 60
)

var (
	ErrInvalidToken     = errors.New("aauth: invalid token")
	ErrWrongTokenType   = errors.New("aauth: wrong token type")
	ErrSignatureInvalid = errors.New("aauth: signature invalid")
	ErrExpired          = errors.New("aauth: token expired")
	ErrMissingSigKey    = errors.New("aauth: missing Signature-Key header")
	ErrBadSigKey        = errors.New("aauth: malformed Signature-Key header")
	ErrMissingClaim     = errors.New("aauth: required claim missing")
	ErrSubAgentDirect   = errors.New("aauth: sub-agent must not request authorization directly")
)
