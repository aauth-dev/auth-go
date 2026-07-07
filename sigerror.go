package aauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Signature-Error (signature-key draft §5): the machine-readable channel for
// signature-related rejections. The header is authoritative; the RFC 9457
// problem+json body is for humans and MAY duplicate header members.

// Signature-Error codes (signature-key draft §5.4).
const (
	SigErrUnsupportedAlgorithm = "unsupported_algorithm"
	SigErrInvalidSignature     = "invalid_signature"
	SigErrInvalidInput         = "invalid_input"
	SigErrKeyNotFound          = "key_not_found"
	SigErrInvalidKey           = "invalid_key"
	SigErrExpiredSignature     = "expired_signature"
)

// SignatureError is a parsed Signature-Error header.
type SignatureError struct {
	// Code is the required error member.
	Code string
	// Params carries code-specific members (e.g. supported_algorithms).
	// Unknown members are preserved; recipients ignore what they don't know.
	Params map[string]string
}

// Error implements error.
func (e *SignatureError) Error() string {
	return "aauth: signature error: " + e.Code
}

// String renders the header value: `error=<code>[, k=v ...]`.
func (e SignatureError) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "error=%s", e.Code)
	for k, v := range e.Params {
		fmt.Fprintf(&b, ", %s=%s", k, v)
	}
	return b.String()
}

// ParseSignatureError parses a Signature-Error header value. Returns nil if
// the value is empty (no signature error present).
func ParseSignatureError(v string) (*SignatureError, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	e := &SignatureError{Params: map[string]string{}}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("aauth: malformed Signature-Error member %q", part)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if key == "error" {
			e.Code = val
		} else {
			e.Params[key] = val
		}
	}
	if e.Code == "" {
		return nil, fmt.Errorf("aauth: Signature-Error missing required error member")
	}
	return e, nil
}

// SignatureErrorFromResponse extracts the Signature-Error from a response,
// or nil when absent.
func SignatureErrorFromResponse(res *http.Response) (*SignatureError, error) {
	return ParseSignatureError(res.Header.Get(HeaderSignatureError))
}

// problemDetails is the RFC 9457 body accompanying a Signature-Error.
type problemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// WriteSignatureError writes the Signature-Error header plus an RFC 9457
// problem+json body. status is typically 400; use 401 for recoverable errors
// (unsupported_algorithm, invalid_input) the client can retry corrected.
//
// Policy denials after successful verification are NOT signature errors —
// return a plain 403 without this header (§5.3).
func WriteSignatureError(w http.ResponseWriter, status int, e SignatureError, detail string) {
	w.Header().Set(HeaderSignatureError, e.String())
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemDetails{
		Type:   "urn:ietf:params:sig-error:" + e.Code,
		Title:  strings.ReplaceAll(e.Code, "_", " "),
		Status: status,
		Detail: detail,
	})
}
