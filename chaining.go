package aauth

import "fmt"

// Call chaining (draft -09 §10.1): a resource that receives an authorized
// request may need to reach a downstream resource to fulfill it. It acts as
// an agent — its own identity and key — and routes the downstream token
// request based on the *upstream* auth token it holds, presenting that token
// as upstream_token so the recipient can extend the authorization downstream.

// ChainRouter tells an intermediary where to send a downstream token request
// and what to carry, derived from the upstream auth token per §10.1.1.
type ChainRouter struct {
	// Endpoint is the PS (or AS) base URL to route the downstream request to.
	Endpoint string
	// UpstreamToken is the raw upstream auth token to send as upstream_token.
	UpstreamToken string
	// Governed reports whether a PS with mission context is in the loop
	// (mission present, or the upstream issuer was a PS). When false, the
	// upstream was an AS with no governance context.
	Governed bool
}

// RouteDownstream computes the routing for a downstream call from the
// verified upstream auth token and its raw form (§10.1.1):
//
//   - mission present → route to mission.approver (the governed path; the PS
//     sees the full delegation chain);
//   - no mission, upstream iss is a PS → route to that PS;
//   - no mission, upstream iss is an AS → route to that AS (no governance).
//
// The ps claim in the calling agent's token is NOT used — the upstream auth
// token is authoritative. isPS reports whether a given issuer URL is a PS
// (vs an AS); pass nil to treat every issuer as a PS (three-party default).
func RouteDownstream(upstream *AuthClaims, rawUpstream string, isPS func(iss string) bool) (ChainRouter, error) {
	if upstream == nil || rawUpstream == "" {
		return ChainRouter{}, fmt.Errorf("aauth: RouteDownstream needs the upstream auth token")
	}
	if upstream.Mission != nil && upstream.Mission.Approver != "" {
		return ChainRouter{Endpoint: upstream.Mission.Approver, UpstreamToken: rawUpstream, Governed: true}, nil
	}
	if upstream.Issuer == "" {
		return ChainRouter{}, fmt.Errorf("aauth: upstream auth token has neither mission nor iss to route from")
	}
	governed := isPS == nil || isPS(upstream.Issuer)
	return ChainRouter{Endpoint: upstream.Issuer, UpstreamToken: rawUpstream, Governed: governed}, nil
}

// NextAct builds the delegation chain (§10.3) for a downstream auth token the
// recipient (PS/AS) is about to issue to the intermediary. upstreamAgent is
// the immediate upstream agent (the caller that presented the upstream
// token); upstreamAct is that upstream token's own act claim, if any, which
// becomes the nested tail.
func NextAct(upstreamAgent string, upstreamAct *ActClaim) *ActClaim {
	if upstreamAgent == "" {
		return nil
	}
	return &ActClaim{Agent: upstreamAgent, Act: upstreamAct}
}
