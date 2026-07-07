package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Agent is a self-hosted agent: it acts as its own agent provider and
// self-issues agent tokens signed by its published key
// (draft-hardt-aauth-bootstrap-01 §4.3). One key serves both as the AP
// signing key and as the cnf.jwk HTTP-signing key.
type Agent struct {
	// ID is the agent identifier (the token's sub), stable across rotations.
	ID AgentIdentifier
	// Issuer is the agent provider URL. For a self-hosted agent this is a
	// domain the operator controls, publishing /.well-known/aauth-agent.json.
	// Empty for purely local deployments verified via SelfSignedResolver.
	Issuer string
	// PS is the agent's Person Server URL (optional ps claim).
	PS string
	// TokenTTL bounds minted tokens; capped at 24h per draft -09 §5.2.2.
	TokenTTL time.Duration

	// Priv is the agent's Ed25519 private key. It signs both self-issued
	// agent tokens and HTTP messages; its public half appears in cnf.jwk.
	Priv ed25519.PrivateKey
	// Pub is the corresponding Ed25519 public key.
	Pub ed25519.PublicKey
}

// NewAgent generates a fresh Ed25519 keypair for the given identifier.
func NewAgent(id AgentIdentifier, opts ...AgentOption) (*Agent, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	a := &Agent{ID: id, TokenTTL: time.Hour, Priv: priv, Pub: pub}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// AgentOption configures NewAgent.
type AgentOption func(*Agent)

// WithIssuer sets the agent-provider URL (self-hosted domain).
func WithIssuer(iss string) AgentOption { return func(a *Agent) { a.Issuer = iss } }

// WithPersonServer sets the ps claim.
func WithPersonServer(ps string) AgentOption { return func(a *Agent) { a.PS = ps } }

// WithKey uses an existing Ed25519 private key instead of generating one.
func WithKey(priv ed25519.PrivateKey) AgentOption {
	return func(a *Agent) {
		a.Priv = priv
		a.Pub = priv.Public().(ed25519.PublicKey)
	}
}

// WithTokenTTL overrides the minted-token lifetime (capped at 24h).
func WithTokenTTL(d time.Duration) AgentOption { return func(a *Agent) { a.TokenTTL = d } }

// JWK returns the agent's public key with Kid = RFC 7638 thumbprint.
func (a *Agent) JWK() JWK { return NewEd25519JWK(a.Pub) }

// Thumbprint is the agent key's RFC 7638 thumbprint.
func (a *Agent) Thumbprint() string { return a.JWK().Thumbprint() }

// JWKS returns the one-key set a self-hosted agent publishes at its jwks_uri.
func (a *Agent) JWKS() JWKS { return JWKS{Keys: []JWK{a.JWK()}} }

// MintToken self-issues an aa-agent+jwt with the draft -09 claim set:
// iss, dwk, sub, jti, cnf.jwk, iat, exp (+ ps when configured).
func (a *Agent) MintToken() (string, error) {
	return a.mint("", time.Now())
}

// MintSubAgentToken issues a token for a short-lived worker under this agent
// (draft -09 §10.2): sub = aauth:name+discriminator@domain, parent_agent set.
// The sub-agent shares consent obtained by the parent but stays individually
// identifiable for audit and revocation.
func (a *Agent) MintSubAgentToken(discriminator string) (string, error) {
	return a.mint(discriminator, time.Now())
}

func (a *Agent) mint(discriminator string, now time.Time) (string, error) {
	ttl := a.TokenTTL
	if max := time.Duration(MaxAgentTokenTTLSeconds) * time.Second; ttl <= 0 || ttl > max {
		ttl = max
	}
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	sub := a.ID
	parent := ""
	if discriminator != "" {
		sub, err = a.ID.SubAgent(discriminator)
		if err != nil {
			return "", err
		}
		parent = a.ID.String()
	}
	jwk := a.JWK()
	claims := AgentClaims{
		DWK:         WellKnownAgent,
		PS:          a.PS,
		ParentAgent: parent,
		Cnf:         Cnf{JWK: &jwk},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.Issuer,
			Subject:   sub.String(),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return MintAgentToken(claims, a.Priv, jwk.Kid)
}

func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("aauth: jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
