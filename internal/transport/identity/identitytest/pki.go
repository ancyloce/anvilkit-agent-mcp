// Package identitytest mints throwaway CAs and leaves for unit tests of the
// identity transport: no Kubernetes, no cert-manager, no files outside the
// test's temporary directory.
package identitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is an in-memory certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// NewCA creates a CA named name.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Leaf is an issued certificate with its key, PEM-encoded.
type Leaf struct {
	CertPEM []byte
	KeyPEM  []byte
}

// Issue signs a leaf with the given URI SANs (none for a certificate without
// a workload identity), DNS names and the loopback address.
func (ca *CA) Issue(t testing.TB, commonName string, uris []string, dnsNames ...string) Leaf {
	t.Helper()
	return ca.IssueFor(t, commonName, uris, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour), dnsNames...)
}

// IssueFor is Issue with an explicit validity.
func (ca *CA) IssueFor(t testing.TB, commonName string, uris []string, notBefore, notAfter time.Time, dnsNames ...string) Leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: commonName},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames: append([]string{"localhost"}, dnsNames...), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// SPIFFE builds the development-shaped identity URI.
func SPIFFE(trustDomain, namespace, sa string) string {
	return "spiffe://" + trustDomain + "/ns/" + namespace + "/sa/" + sa
}

// Mount writes tls.crt, tls.key and ca.crt into dir the way the kubelet
// mounts a Secret: a timestamped directory, a ..data symlink swapped
// atomically and stable file names that are symlinks into ..data. Repeated
// calls on the same dir are rotations.
func Mount(t testing.TB, dir string, leaf Leaf, caBundle []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ts, err := os.MkdirTemp(dir, "..ts-")
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"tls.crt": leaf.CertPEM, "tls.key": leaf.KeyPEM, "ca.crt": caBundle} {
		if err := os.WriteFile(filepath.Join(ts, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tmp := filepath.Join(dir, "..data_tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Base(ts), tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); err != nil {
			if err := os.Symlink(filepath.Join("..data", name), p); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Files names the mounted paths of dir.
func Files(dir string) (cert, key, ca string) {
	return filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt")
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
