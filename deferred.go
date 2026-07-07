package aauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Deferred responses (draft -09 §12.4): any AAuth endpoint MAY answer
// 202 Accepted with a Location pending URL when it cannot resolve a request
// immediately — the protocol's first-class "wait for the human" primitive.
// The agent then polls the pending URL with signed GETs, honoring
// Retry-After, backing off linearly on 429 (per RFC 8628 §3.5's pattern),
// until a non-202 terminal response arrives.

// PendingStatus is the body of a 202 pending response.
type PendingStatus struct {
	// Status is "pending", or "interacting" once the user has arrived at an
	// interaction endpoint. Unrecognized values MUST be treated as pending.
	Status string `json:"status"`
}

// DeferredOptions tunes DoDeferred.
type DeferredOptions struct {
	// PreferWaitSeconds is sent as `Prefer: wait=N` on polling GETs to
	// request long-poll behavior. 0 omits the header.
	PreferWaitSeconds int
	// DefaultPollInterval applies when a 202 carries no Retry-After
	// (spec default: 5s).
	DefaultPollInterval time.Duration
	// MaxPolls bounds the polling loop as a safety valve. 0 = unbounded
	// (the context deadline is then the only limit).
	MaxPolls int
	// Sign re-signs each polling GET. Deferred polling of a signed endpoint
	// keeps presenting the agent's identity; leave nil for unsigned polls.
	Sign func(*http.Request) error
	// OnRequirement is invoked once per distinct AAuth-Requirement header
	// seen on a 202 (e.g. requirement=interaction; url=…; code=…) so the
	// caller can surface the interaction to the user while polling continues.
	OnRequirement func(Requirement)
}

// DoDeferred executes req and follows the §12.4 state machine until a
// terminal (non-202) response. The caller owns closing the returned body.
func DoDeferred(ctx context.Context, hc *http.Client, req *http.Request, opts DeferredOptions) (*http.Response, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	return FollowDeferred(ctx, hc, req.URL, res, opts)
}

// FollowDeferred continues the §12.4 state machine from an already-received
// response: if res is not a 202 it is returned unchanged; otherwise the
// pending URL is polled until a terminal response arrives. reqURL is the URL
// the original request was sent to (for same-origin Location resolution).
func FollowDeferred(ctx context.Context, hc *http.Client, reqURL *url.URL, res *http.Response, opts DeferredOptions) (*http.Response, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if opts.DefaultPollInterval <= 0 {
		opts.DefaultPollInterval = 5 * time.Second
	}
	backoff := time.Duration(0)
	polls := 0
	lastReq := ""

	for res.StatusCode == http.StatusAccepted {
		if opts.OnRequirement != nil {
			if rh := res.Header.Get(HeaderRequirement); rh != "" && rh != lastReq {
				lastReq = rh
				if parsed, perr := ParseRequirement(rh); perr == nil {
					opts.OnRequirement(parsed)
				}
			}
		}
		pendingURL, retryAfter, err := readPending(reqURL, res)
		if err != nil {
			return nil, err
		}
		if opts.MaxPolls > 0 && polls >= opts.MaxPolls {
			return nil, fmt.Errorf("aauth: deferred response still pending after %d polls", polls)
		}
		wait := retryAfter
		if wait < 0 {
			wait = opts.DefaultPollInterval
		}
		wait += backoff
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}

		poll, err := http.NewRequestWithContext(ctx, http.MethodGet, pendingURL.String(), nil)
		if err != nil {
			return nil, err
		}
		if opts.PreferWaitSeconds > 0 {
			poll.Header.Set(HeaderPrefer, fmt.Sprintf("wait=%d", opts.PreferWaitSeconds))
		}
		if opts.Sign != nil {
			if err := opts.Sign(poll); err != nil {
				return nil, fmt.Errorf("aauth: sign poll: %w", err)
			}
		}
		res, err = hc.Do(poll)
		if err != nil {
			return nil, err
		}
		polls++
		if res.StatusCode == http.StatusTooManyRequests {
			// Linear backoff: increase interval by 5s (spec §12.4.3).
			backoff += 5 * time.Second
			res.Body.Close()
			res = &http.Response{StatusCode: http.StatusAccepted, Header: res.Header, Body: http.NoBody, Request: poll}
			// Reuse the same pending URL on the next iteration.
			res.Header.Set(HeaderLocation, pendingURL.String())
			if res.Header.Get(HeaderRetryAfter) == "" {
				res.Header.Set(HeaderRetryAfter, "0")
			}
		}
	}
	return res, nil
}

// readPending validates a 202 response and extracts the same-origin pending
// URL and Retry-After. Returns retryAfter=-1 when the header is absent.
func readPending(reqURL *url.URL, res *http.Response) (*url.URL, time.Duration, error) {
	defer res.Body.Close()
	loc := res.Header.Get(HeaderLocation)
	if loc == "" {
		return nil, 0, fmt.Errorf("aauth: 202 without Location")
	}
	u, err := reqURL.Parse(loc)
	if err != nil {
		return nil, 0, fmt.Errorf("aauth: 202 Location: %w", err)
	}
	// Location MUST be same-origin as the responding server (§12.4.2).
	if u.Scheme != reqURL.Scheme || u.Host != reqURL.Host {
		return nil, 0, fmt.Errorf("aauth: 202 Location %q not same-origin as %q", u, reqURL)
	}
	retry := time.Duration(-1)
	if ra := res.Header.Get(HeaderRetryAfter); ra != "" {
		sec, err := strconv.Atoi(ra)
		if err != nil || sec < 0 {
			return nil, 0, fmt.Errorf("aauth: bad Retry-After %q", ra)
		}
		retry = time.Duration(sec) * time.Second
	}
	// Drain the pending body (status field is informational; unrecognized
	// statuses are treated as pending per §12.4.2).
	var ps PendingStatus
	_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&ps)
	return u, retry, nil
}
