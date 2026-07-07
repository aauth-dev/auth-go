package aauth

import (
	"encoding/json"
	"net/http"
)

// Interaction chaining (draft -09 §10.1.2): when a resource acting as an
// agent receives a downstream requirement=interaction it cannot satisfy
// itself, it propagates the interaction to its own caller by returning its
// own 202 — its own Location (for the caller to poll) and its own
// interaction code. When the user completes the interaction and the resource
// obtains the downstream token, it finishes the original request at its
// pending URL.
//
// ChainInteraction writes that propagating 202. pendingURL and code are the
// resource's own (not the downstream's); status defaults to "pending".
func ChainInteraction(w http.ResponseWriter, pendingURL, interactionURL, code string) {
	w.Header().Set(HeaderLocation, pendingURL)
	w.Header().Set(HeaderRetryAfter, "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(HeaderRequirement, Requirement{
		Requirement: RequirementInteraction,
		URL:         interactionURL,
		Code:        code,
	}.String())
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(PendingStatus{Status: "pending"})
}

// WriteClarification writes a requirement=clarification 202 (§7.3.1) asking
// the recipient a question. options may be nil; timeout 0 omits the field.
func WriteClarification(w http.ResponseWriter, pendingURL, question string, timeout int, options []string) {
	w.Header().Set(HeaderLocation, pendingURL)
	w.Header().Set(HeaderRetryAfter, "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(HeaderRequirement, Requirement{Requirement: RequirementClarification}.String())
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(PendingStatus{
		Status:        "pending",
		Clarification: question,
		Timeout:       timeout,
		Options:       options,
	})
}

// ClarificationPost is a parsed agent response to a clarification (§7.3.2),
// read from a POST to the pending URL. Action is one of
// ActionClarificationResponse or ActionUpdatedRequest.
type ClarificationPost struct {
	Action                string `json:"action"`
	ClarificationResponse string `json:"clarification_response,omitempty"`
	ResourceToken         string `json:"resource_token,omitempty"`
	Justification         string `json:"justification,omitempty"`
}

// ParseClarificationPost decodes a POST body to the pending URL and validates
// the action member (§7.3.2: a missing or unrecognized action is a 400).
func ParseClarificationPost(r *http.Request) (*ClarificationPost, error) {
	var p ClarificationPost
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		return nil, err
	}
	switch p.Action {
	case ActionClarificationResponse, ActionUpdatedRequest:
		return &p, nil
	default:
		return nil, ErrUnknownAction
	}
}
