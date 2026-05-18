package integrity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Ed25519 sign/verify helpers built on canonical JSON. The canonical
// form is the output of `json.MarshalIndent(v, "", "  ")` with
// signature fields zeroed out. encoding/json sorts map[string]X keys
// alphabetically and struct fields follow declaration order, so the
// byte sequence is deterministic across processes.

// SignBytes signs canonicalBytes with priv and returns a
// base64-encoded signature, suitable for embedding in a JSON
// `signature` field.
func SignBytes(priv ed25519.PrivateKey, canonicalBytes []byte) string {
	sig := ed25519.Sign(priv, canonicalBytes)
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifyBytes checks the base64-encoded signature against
// canonicalBytes using pub. Returns nil on success.
func VerifyBytes(pub ed25519.PublicKey, canonicalBytes []byte, b64sig string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("verify: public key wrong size")
	}
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return errors.New("verify: signature not valid base64")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("verify: signature wrong size")
	}
	if !ed25519.Verify(pub, canonicalBytes, sig) {
		return errors.New("verify: signature does not match")
	}
	return nil
}

// CanonicalJSON returns a deterministic JSON encoding suitable for
// signing. Map keys are sorted; struct fields use declaration order.
// Trailing newline omitted so signatures are independent of pretty
// printing.
func CanonicalJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
