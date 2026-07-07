package aauth

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"

	"github.com/yaronf/httpsign"
)

// The AAuth HTTP message-signature profile (draft -09 §12.7): every request
// is signed with the key from cnf.jwk, covering exactly the four mandated
// components (each closes a request-substitution attack):
//
//	@method, @authority, @path, signature-key
//
// content-digest is added when the request has a body — permitted as an
// additional component (resources advertise extras via
// additional_signature_components in their metadata).
func coveredFields(hasBody bool) httpsign.Fields {
	base := []string{"@method", "@authority", "@path", "signature-key"}
	if hasBody {
		base = append(base, "content-digest")
	}
	return httpsign.Headers(base...)
}

// ContentDigestAlg is the digest algorithm for the Content-Digest header.
const ContentDigestAlg = "sha-256"

// AttachSignatureKey sets the Signature-Key header carrying the agent (or
// auth) token via scheme=jwt (signature-key draft §3.6). The dictionary key
// is the signature label (§3: labels correlate across Signature-Input,
// Signature, and Signature-Key).
func AttachSignatureKey(req *http.Request, token string) {
	req.Header.Set(HeaderSignatureKey, fmt.Sprintf(`%s=jwt; jwt=%q`, DefaultSignatureLabel, token))
}

// ParseSignatureKey extracts the scheme=jwt token for the default label.
func ParseSignatureKey(req *http.Request) (string, error) {
	h := req.Header.Get(HeaderSignatureKey)
	if h == "" {
		return "", ErrMissingSigKey
	}
	// Structured-field dictionary member: <label>=jwt;jwt="<token>".
	// Accept whitespace variance between parameters.
	idx := strings.Index(h, DefaultSignatureLabel+"=jwt")
	if idx < 0 {
		return "", ErrBadSigKey
	}
	rest := h[idx:]
	jidx := strings.Index(rest, `jwt="`)
	if jidx < 0 {
		return "", ErrBadSigKey
	}
	rest = rest[jidx+len(`jwt="`):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", ErrBadSigKey
	}
	if rest[:end] == "" {
		return "", ErrBadSigKey
	}
	return rest[:end], nil
}

// SignRequest signs req per the AAuth profile: sets Content-Digest when a
// body is present, then Signature-Input and Signature under the default
// label. The Signature-Key header MUST already be attached (it is a covered
// component). keyid is set to the signing key's RFC 7638 thumbprint.
func SignRequest(req *http.Request, priv ed25519.PrivateKey, keyid string) error {
	if req.Header.Get(HeaderSignatureKey) == "" {
		return ErrMissingSigKey
	}
	hasBody := req.Body != nil && req.ContentLength != 0
	if hasBody && req.Header.Get("Content-Digest") == "" {
		d, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{ContentDigestAlg})
		if err != nil {
			return fmt.Errorf("aauth: content-digest: %w", err)
		}
		req.Header.Set("Content-Digest", d)
	}
	cfg := httpsign.NewSignConfig().SetKeyID(keyid).SignAlg(false).SignCreated(true)
	signer, err := httpsign.NewEd25519Signer(priv, cfg, coveredFields(hasBody))
	if err != nil {
		return err
	}
	input, sig, err := httpsign.SignRequest(DefaultSignatureLabel, *signer, req)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderSignatureInput, input)
	req.Header.Set(HeaderSignature, sig)
	return nil
}

// VerifyRequest verifies the HTTP message signature against pub, requiring
// the mandated component coverage.
func VerifyRequest(req *http.Request, pub ed25519.PublicKey) error {
	// No SetAllowedAlgs: AAuth derives the algorithm from the key's JWK alg
	// (draft -09 §12.7.1) rather than a signed alg parameter; the Ed25519
	// verifier construction below pins the algorithm.
	cfg := httpsign.NewVerifyConfig().SetVerifyCreated(false)
	v, err := httpsign.NewEd25519Verifier(pub, cfg, coveredFields(false))
	if err != nil {
		return err
	}
	if err := httpsign.VerifyRequest(DefaultSignatureLabel, *v, req); err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	if cds := req.Header.Values("Content-Digest"); len(cds) > 0 && req.Body != nil {
		if err := httpsign.ValidateContentDigestHeader(cds, &req.Body, []string{ContentDigestAlg}); err != nil {
			return fmt.Errorf("%w: content-digest: %w", ErrSignatureInvalid, err)
		}
	}
	return nil
}

// VerifyAndExtractAgent is the server-side entry point: parse Signature-Key,
// verify the agent token (via opts.Resolver), then verify the HTTP message
// signature against the token's cnf.jwk (draft -09 §5.2.4 steps 1–5).
func VerifyAndExtractAgent(ctx context.Context, req *http.Request, opts VerifyAgentTokenOptions) (*AgentClaims, error) {
	token, err := ParseSignatureKey(req)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyAgentToken(ctx, token, opts)
	if err != nil {
		return nil, err
	}
	pub, err := claims.Cnf.JWK.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := VerifyRequest(req, pub); err != nil {
		return nil, err
	}
	return claims, nil
}
