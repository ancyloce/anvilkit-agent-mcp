package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// Files names the mounted identity material: the workload's certificate
// chain and private key and the bundle of CAs it trusts (client CAs on a
// server, server CAs on a client). Mounted Secrets replace them through a
// ..data symlink swap; the files are always read by path.
type Files struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// Material is one complete, validated identity configuration. It is
// immutable; a reload produces a new value or none.
type Material struct {
	Certificate tls.Certificate
	Leaf        *x509.Certificate
	Pool        *x509.CertPool
	// Roots are the trusted CA certificates keyed by their SHA-256
	// fingerprint; a peer chain is accepted only while its root is here.
	Roots map[[32]byte]*x509.Certificate
	// Digest covers the three files' bytes; equal digests mean nothing changed.
	Digest [32]byte
}

// TrustsRoot reports whether the root of a verified chain is still trusted.
func (m *Material) TrustsRoot(root *x509.Certificate) bool {
	if m == nil || root == nil {
		return false
	}
	_, ok := m.Roots[sha256.Sum256(root.Raw)]
	return ok
}

// Load reads and validates the files as a whole: the key must match the
// certificate, the leaf must be within its validity, and the bundle must
// hold at least one CA certificate. Any defect rejects the candidate.
func Load(f Files, now time.Time) (*Material, error) {
	certPEM, err := os.ReadFile(f.CertFile)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(f.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	caPEM, err := os.ReadFile(f.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	return Parse(certPEM, keyPEM, caPEM, now)
}

// Parse validates in-memory PEM material (Load's core; tests feed it directly).
func Parse(certPEM, keyPEM, caPEM []byte, now time.Time) (*Material, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("leaf: %w", err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("leaf is not valid at %s (valid %s to %s)", now.UTC().Format(time.RFC3339), leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	cert.Leaf = leaf
	pool := x509.NewCertPool()
	roots := map[[32]byte]*x509.Certificate{}
	rest := caPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca bundle: %w", err)
		}
		if !ca.IsCA {
			return nil, fmt.Errorf("ca bundle holds a non-CA certificate (%s)", ca.Subject.String())
		}
		pool.AddCert(ca)
		roots[sha256.Sum256(ca.Raw)] = ca
	}
	if len(roots) == 0 {
		return nil, errors.New("ca bundle holds no certificate")
	}
	h := sha256.New()
	for _, b := range [][]byte{certPEM, keyPEM, caPEM} {
		h.Write(b)
		h.Write([]byte{0})
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return &Material{Certificate: cert, Leaf: leaf, Pool: pool, Roots: roots, Digest: digest}, nil
}

// filesDigest hashes the current file bytes without validating them, so a
// poll that sees unchanged bytes does nothing.
func filesDigest(f Files) ([32]byte, error) {
	h := sha256.New()
	for _, p := range []string{f.CertFile, f.KeyFile, f.CAFile} {
		b, err := os.ReadFile(p)
		if err != nil {
			return [32]byte{}, err
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d, nil
}

// Equal reports whether two materials are the same files' content.
func (m *Material) Equal(o *Material) bool {
	return m != nil && o != nil && bytes.Equal(m.Digest[:], o.Digest[:])
}
