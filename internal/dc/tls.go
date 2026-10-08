package dc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// renewBefore: a self-signed certificate is renewed at start when it
// expires within this time.
const renewBefore = 30 * 24 * time.Hour

// Lifetimes of the self-signed CA and of the certificates it issues.
const (
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 397 * 24 * time.Hour
)

// serviceCerts are the web certificates the self-signed CA issues for the
// stack (name -> first label of the DNS name).
var serviceCerts = []string{"conductor", "idp"}

// tlsPaths of the DC certificate (where smb.conf names them).
func tlsPaths(privateDir string) (key, cert, ca string) {
	d := filepath.Join(privateDir, "tls")
	return filepath.Join(d, "key.pem"), filepath.Join(d, "cert.pem"), filepath.Join(d, "ca.pem")
}

// ensureTLS installs or renews the DC's certificate and exports the CA.
func (r *Runner) ensureTLS(privateDir string) error {
	if r.Cfg.TLS == "provided" {
		return r.installProvidedTLS(privateDir)
	}
	return r.ensureSelfSigned(privateDir)
}

func (r *Runner) installProvidedTLS(privateDir string) error {
	keyP, certP, caP := tlsPaths(privateDir)
	files := map[string]struct {
		dst  string
		mode fs.FileMode
	}{
		"dc-tls-key":  {keyP, 0o600},
		"dc-tls-cert": {certP, 0o644},
		"dc-tls-ca":   {caP, 0o644},
	}
	if err := os.MkdirAll(filepath.Dir(keyP), 0o700); err != nil {
		return err
	}
	for name, f := range files {
		b, err := os.ReadFile(filepath.Join(SecretsDir, name))
		if err != nil {
			return fmt.Errorf("SC_TLS=provided needs the secret %s: %w", name, err)
		}
		if err := writeFileAtomic(f.dst, b, f.mode); err != nil {
			return err
		}
	}
	cert, err := readCert(certP)
	if err != nil {
		return fmt.Errorf("dc-tls-cert: %w", err)
	}
	if err := cert.VerifyHostname(r.Cfg.FQDN()); err != nil {
		return fmt.Errorf("dc-tls-cert does not name %s: %w", r.Cfg.FQDN(), err)
	}
	if time.Until(cert.NotAfter) < renewBefore {
		r.logf("WARNING: the provided DC certificate expires on %s", cert.NotAfter.Format(time.DateOnly))
	}
	return r.exportCA(caP)
}

// ensureSelfSigned creates the CA once (name-constrained to the realm and
// SC_HOST_IP, so it cannot vouch for anything else) and the DC and service
// certificates, renewing any that is close to expiry or names something
// else than the current configuration.
func (r *Runner) ensureSelfSigned(privateDir string) error {
	caKey, caCert, err := r.loadOrCreateCA()
	if err != nil {
		return err
	}
	keyP, certP, caP := tlsPaths(privateDir)
	if err := os.MkdirAll(filepath.Dir(keyP), 0o700); err != nil {
		return err
	}
	dns := []string{r.Cfg.FQDN(), r.Cfg.DNSDomain()}
	if err := r.ensureLeaf(caKey, caCert, keyP, certP, r.Cfg.FQDN(), dns); err != nil {
		return err
	}
	if err := writeFileAtomic(caP, pemCert(caCert), 0o644); err != nil {
		return err
	}
	for _, name := range serviceCerts {
		dir := filepath.Join(IssuedDir, name)
		if _, err := os.Stat(IssuedDir); err != nil {
			continue // the volume is not mounted: no service certificates wanted
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		host := name + "." + r.Cfg.DNSDomain()
		if err := r.ensureLeaf(caKey, caCert, filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem"), host, []string{host}); err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(dir, "ca.pem"), pemCert(caCert), 0o644); err != nil {
			return err
		}
	}
	return r.exportCA(caP)
}

func (r *Runner) loadOrCreateCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	keyP, certP := filepath.Join(CADir, "ca.key"), filepath.Join(CADir, "ca.pem")
	if cert, err := readCert(certP); err == nil {
		key, kerr := readKey(keyP)
		if kerr != nil {
			return nil, nil, fmt.Errorf("self-signed CA: %w", kerr)
		}
		if !caCovers(cert, r.Cfg.DNSDomain(), r.Cfg.HostIP) {
			return nil, nil, fmt.Errorf("the self-signed CA on the volume is constrained to other names than %s and %s; "+
				"a changed SC_REALM or SC_HOST_IP needs new certificates for every client (remove %s to start a new CA)", r.Cfg.DNSDomain(), r.Cfg.HostIP, CADir)
		}
		if time.Until(cert.NotAfter) < renewBefore {
			r.logf("WARNING: the self-signed CA expires on %s; remove %s and restart to create a new one (clients must trust the new CA)", cert.NotAfter.Format(time.DateOnly), CADir)
		}
		return key, cert, nil
	}
	if err := os.MkdirAll(CADir, 0o700); err != nil {
		return nil, nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	_, ipNet, err := net.ParseCIDR(r.Cfg.HostIP + "/32")
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{Organization: []string{"Samba Conductor"}, CommonName: "Samba Conductor CA for " + r.Cfg.Realm},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(caLifetime),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{r.Cfg.DNSDomain()},
		PermittedIPRanges:           []*net.IPNet{ipNet},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	if err := writeFileAtomic(keyP, pemKey(key), 0o600); err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(certP, pemCert(cert), 0o644); err != nil {
		return nil, nil, err
	}
	r.logf("created a self-signed CA (constrained to %s and %s)", r.Cfg.DNSDomain(), r.Cfg.HostIP)
	return key, cert, nil
}

// caCovers reports whether the CA's name constraints admit the domain and
// the address.
func caCovers(ca *x509.Certificate, domain, ip string) bool {
	if !slices.Contains(ca.PermittedDNSDomains, domain) {
		return false
	}
	addr := net.ParseIP(ip)
	for _, n := range ca.PermittedIPRanges {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// ensureLeaf issues keyP/certP unless a current certificate with the same
// names, from this CA, valid for more than renewBefore, is there.
func (r *Runner) ensureLeaf(caKey *rsa.PrivateKey, ca *x509.Certificate, keyP, certP, cn string, dns []string) error {
	ip := net.ParseIP(r.Cfg.HostIP)
	if cur, err := readCert(certP); err == nil {
		same := cur.CheckSignatureFrom(ca) == nil && slices.Equal(cur.DNSNames, dns) &&
			len(cur.IPAddresses) == 1 && cur.IPAddresses[0].Equal(ip) && time.Until(cur.NotAfter) > renewBefore
		if _, kerr := readKey(keyP); same && kerr == nil {
			return nil
		}
		r.logf("renewing the certificate for %s", cn)
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	cert, _ := x509.ParseCertificate(der)
	if err := writeFileAtomic(keyP, pemKey(key), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(certP, pemCert(cert), 0o644)
}

// exportCA publishes the CA (and the realm's krb5.conf, done elsewhere)
// for the other containers and logs its fingerprint.
func (r *Runner) exportCA(caP string) error {
	b, err := os.ReadFile(caP)
	if err != nil {
		return err
	}
	if _, err := os.Stat(PublicDir); err == nil {
		if err := writeFileAtomic(filepath.Join(PublicDir, "ca.pem"), b, 0o644); err != nil {
			return err
		}
	}
	if c, err := readCert(caP); err == nil {
		sum := sha256.Sum256(c.Raw)
		r.logf("domain CA SHA-256 fingerprint: %s", colonHex(sum[:]))
	}
	return nil
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func pemKey(k *rsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func readCert(p string) (*x509.Certificate, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate", p)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func readKey(p string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM key", p)
	}
	var k any
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("%s: unexpected PEM block %s", p, blk.Type)
	}
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New(p + ": not an RSA key")
	}
	return rk, nil
}

// writeFileAtomic writes a file through a temporary file in its directory.
func writeFileAtomic(path string, b []byte, mode fs.FileMode) error {
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, b) {
		return os.Chmod(path, mode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sc-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
