package main

// Engine: CA state, key/cert/CRL management. All X.509 work uses the Go
// stdlib; openssl is called only for container formats Go lacks:
// pkcs12 export and passphrase-encrypted pkcs8 keys.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	rootKeyPath   = "ca-root/keys/casinha-ca-root.key"
	rootCertPath  = "ca-root/certs/casinha-ca-root.crt"
	rootCrlPath   = "ca-root/crls/casinha-ca-root.crl"
	signKeyPath   = "ca-sign/keys/casinha-ca-sign.key"
	signCertPath  = "ca-sign/certs/casinha-ca-sign.crt"
	signCrlPath   = "ca-sign/crls/casinha-ca-sign.crl"
	signChainPath = "ca-sign/certs/casinha-ca-chain.pem"
	statePath     = "state.json"
	certValidity  = 730 * 24 * time.Hour
	caValidity    = 10 * 365 * 24 * time.Hour
	signCrlWindow = 90 * 24 * time.Hour
	rootCrlWindow = 365 * 24 * time.Hour
	envPassName   = "CASINHA_PW"
	envPassP12    = "CASINHA_P12"
)

// CertRecord tracks one issued certificate.
type CertRecord struct {
	Serial     string    `json:"serial"` // hex
	Kind       string    `json:"kind"`   // "server" or "user"
	Name       string    `json:"name"`   // fqdn or email
	CommonName string    `json:"cn"`
	Email      string    `json:"email,omitempty"`
	NotAfter   time.Time `json:"notAfter"`
	Revoked    bool      `json:"revoked,omitempty"`
	RevokedAt  time.Time `json:"revokedAt,omitempty"`
}

// State is the CA's own bookkeeping, replacing openssl's index database.
type State struct {
	CRLNumber int64        `json:"crlNumber"`
	Certs     []CertRecord `json:"certs"`
}

func loadState() (*State, error) {
	st := &State{CRLNumber: 0}
	data, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("corrupt %s: %w", statePath, err)
	}
	return st, nil
}

func saveState(st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath, data, 0600)
}

func ensureDirs() error {
	dirs := []string{
		"ca-root/keys", "ca-root/certs", "ca-root/crls",
		"ca-sign/keys", "ca-sign/certs", "ca-sign/crls",
		"servers/keys", "servers/csrs", "servers/certs", "servers/p12",
		"users/keys", "users/csrs", "users/certs", "users/p12",
		"logs",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return nil
}

// runOpenSSL runs the openssl CLI. stdin may be nil; envPW entries are
// passed via the environment so passwords never appear in the argv.
func runOpenSSL(stdin []byte, envPW map[string]string, args ...string) ([]byte, error) {
	cmd := exec.Command("openssl", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Env = os.Environ()
	for k, v := range envPW {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("openssl %s failed: %s",
			strings.Join(args, " "), strings.TrimSpace(errOut.String()))
	}
	return out.Bytes(), nil
}

// writeEncryptedKey exports an EC private key as passphrase-encrypted
// PKCS#8 (AES-256) via the openssl CLI.
func writeEncryptedKey(key *ecdsa.PrivateKey, path, pass string, logs *[]string) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	out, err := runOpenSSL(pemBytes, map[string]string{envPassName: pass},
		"pkcs8", "-topk8", "-v2", "aes256", "-inform", "pem",
		"-passout", "env:"+envPassName)
	if err != nil {
		return err
	}
	*logs = append(*logs, "key written: "+path)
	return os.WriteFile(path, out, 0600)
}

// readPrivateKey loads a (possibly encrypted) PKCS#8 key file.
func readPrivateKey(path, pass string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out, err := runOpenSSL(data, map[string]string{envPassName: pass},
		"pkey", "-passin", "env:"+envPassName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(out)
	if block == nil {
		return nil, errors.New("could not decode private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}
	return signer, nil
}

func newSerial() *big.Int {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return s
}

// subjectKeyId derives the SHA-1 key identifier from a public key.
func subjectKeyId(pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha1.Sum(der)
	return sum[:]
}

func writePEM(path, blockType string, der []byte, logs *[]string) error {
	out := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	*logs = append(*logs, "written: "+path)
	return os.WriteFile(path, out, 0600)
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("could not decode %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// NewCA creates the root and intermediate CAs.
func NewCA(rootPass, signPass string) ([]string, error) {
	logs := []string{}
	if _, err := os.Stat(rootCertPath); err == nil {
		return logs, errors.New("CA already exists in this directory")
	}
	if rootPass == "" || signPass == "" {
		return logs, errors.New("passphrases must not be empty")
	}
	if err := ensureDirs(); err != nil {
		return logs, err
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return logs, err
	}
	if err := writeEncryptedKey(rootKey, rootKeyPath, rootPass, &logs); err != nil {
		return logs, err
	}

	rootTmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{Organization: []string{"Casinha"}, CommonName: "Casinha Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1, // no pathLen limit on the root
		SubjectKeyId:          subjectKeyId(&rootKey.PublicKey),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return logs, err
	}
	if err := writePEM(rootCertPath, "CERTIFICATE", rootDER, &logs); err != nil {
		return logs, err
	}
	rootParsed, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return logs, err
	}

	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return logs, err
	}
	if err := writeEncryptedKey(signKey, signKeyPath, signPass, &logs); err != nil {
		return logs, err
	}
	signTmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{Organization: []string{"Casinha"}, CommonName: "Casinha Signing CA"},
		NotBefore:             rootTmpl.NotBefore,
		NotAfter:              rootTmpl.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // pathLen:0 - cannot sign further CAs
		SubjectKeyId:          subjectKeyId(&signKey.PublicKey),
		AuthorityKeyId:        rootTmpl.SubjectKeyId,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	signDER, err := x509.CreateCertificate(rand.Reader, signTmpl, rootParsed, &signKey.PublicKey, rootKey)
	if err != nil {
		return logs, err
	}
	if err := writePEM(signCertPath, "CERTIFICATE", signDER, &logs); err != nil {
		return logs, err
	}
	signParsed, err := x509.ParseCertificate(signDER)
	if err != nil {
		return logs, err
	}

	// chain: intermediate + root
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signDER})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if err := os.WriteFile(signChainPath, chain, 0600); err != nil {
		return logs, err
	}
	logs = append(logs, "written: "+signChainPath)

	// empty CRLs for both CAs
	rootCrlDER, err := x509.CreateRevocationList(rand.Reader,
		&x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(rootCrlWindow)},
		rootParsed, rootKey)
	if err != nil {
		return logs, err
	}
	if err := writePEM(rootCrlPath, "X509 CRL", rootCrlDER, &logs); err != nil {
		return logs, err
	}
	if err := regenerateSignCRL(signParsed, signKey, &State{}, &logs); err != nil {
		return logs, err
	}

	st := &State{CRLNumber: 1}
	if err := saveState(st); err != nil {
		return logs, err
	}
	logs = append(logs, "CA created")
	return logs, nil
}

func regenerateSignCRL(signParsed *x509.Certificate, signKey crypto.Signer, st *State, logs *[]string) error {
	st.CRLNumber++
	entries := []x509.RevocationListEntry{}
	for _, c := range st.Certs {
		if !c.Revoked {
			continue
		}
		raw, err := hex.DecodeString(c.Serial)
		if err != nil {
			return err
		}
		serial := new(big.Int).SetBytes(raw)
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: c.RevokedAt,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SerialNumber.Cmp(entries[j].SerialNumber) < 0
	})
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(st.CRLNumber),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(signCrlWindow),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, signParsed, signKey)
	if err != nil {
		return err
	}
	return writePEM(signCrlPath, "X509 CRL", der, logs)
}

func RegenerateCRL(signPass string) ([]string, error) {
	logs := []string{}
	if err := ensureDirs(); err != nil {
		return logs, err
	}
	signParsed, err := readCert(signCertPath)
	if err != nil {
		return logs, err
	}
	signKey, err := readPrivateKey(signKeyPath, signPass)
	if err != nil {
		return logs, fmt.Errorf("could not read signing CA key (wrong passphrase?): %w", err)
	}
	st, err := loadState()
	if err != nil {
		return logs, err
	}
	if err := regenerateSignCRL(signParsed, signKey, st, &logs); err != nil {
		return logs, err
	}
	logs = append(logs, "CRL regenerated")
	return logs, nil
}

func Revoke(kind, name, signPass string) ([]string, error) {
	logs := []string{}
	if err := ensureDirs(); err != nil {
		return logs, err
	}
	st, err := loadState()
	if err != nil {
		return logs, err
	}
	found := false
	for i := range st.Certs {
		c := &st.Certs[i]
		if c.Kind == kind && c.Name == name {
			if c.Revoked {
				return logs, fmt.Errorf("certificate for %s is already revoked", name)
			}
			c.Revoked = true
			c.RevokedAt = time.Now()
			found = true
			break
		}
	}
	if !found {
		return logs, fmt.Errorf("no issued %s certificate for %s", kind, name)
	}

	signParsed, err := readCert(signCertPath)
	if err != nil {
		return logs, err
	}
	signKey, err := readPrivateKey(signKeyPath, signPass)
	if err != nil {
		return logs, fmt.Errorf("could not read signing CA key (wrong passphrase?): %w", err)
	}
	if err := regenerateSignCRL(signParsed, signKey, st, &logs); err != nil {
		return logs, err
	}
	if err := saveState(st); err != nil {
		return logs, err
	}
	logs = append(logs, fmt.Sprintf("certificate for %s revoked; CRL updated", name))
	return logs, nil
}

// issueCert is the shared path for server and user certificates.
// User keys are passphrase-protected PKCS#8; server keys are plain.
func issueCert(kind, name, cn, email, keyPass, signPass, p12Pass string) ([]string, error) {
	logs := []string{}
	if err := ensureDirs(); err != nil {
		return logs, err
	}
	kindDir := "servers"
	if kind == "user" {
		kindDir = "users"
	}
	keyPath := kindDir + "/keys/" + name + ".key"
	csrPath := kindDir + "/csrs/" + name + ".csr"
	crtPath := kindDir + "/certs/" + name + ".crt"
	chainPath := kindDir + "/certs/" + name + "-chain.pem"
	p12Path := kindDir + "/p12/" + name + ".p12"

	// broken state: without the key, the other artifacts are useless;
	// without the cert, chain and p12 are stale.
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		for _, f := range []string{csrPath, crtPath, chainPath, p12Path} {
			if _, err := os.Stat(f); err == nil {
				_ = os.Remove(f)
				logs = append(logs, "removed "+f+" (no matching key)")
			}
		}
	} else if _, err := os.Stat(crtPath); errors.Is(err, os.ErrNotExist) {
		for _, f := range []string{chainPath, p12Path} {
			if _, err := os.Stat(f); err == nil {
				_ = os.Remove(f)
				logs = append(logs, "removed "+f+" (stale, certificate will be reissued)")
			}
		}
	} else {
		return logs, fmt.Errorf("certificate for %s already exists", name)
	}

	// key
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return logs, err
		}
		if kind == "user" {
			if err := writeEncryptedKey(key, keyPath, keyPass, &logs); err != nil {
				return logs, err
			}
		} else {
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return logs, err
			}
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
				return logs, err
			}
			logs = append(logs, "key written: "+keyPath)
		}
	}

	// csr
	if _, err := os.Stat(csrPath); errors.Is(err, os.ErrNotExist) {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return logs, err
		}
		var keyObj crypto.PrivateKey
		if kind == "user" {
			keyObj, err = readPrivateKey(keyPath, keyPass)
		} else {
			block, _ := pem.Decode(keyData)
			keyObj, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if err != nil {
			return logs, err
		}
		subject := pkix.Name{Organization: []string{"Casinha"}, CommonName: cn}
		if kind == "user" {
			// emailAddress goes through ExtraNames: pkix.Name has no
			// dedicated field (OID 1.2.840.113549.1.9.1)
			subject.ExtraNames = []pkix.AttributeTypeAndValue{{
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: email,
			}}
		}
		tmpl := x509.CertificateRequest{
			Subject:            subject,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, keyObj)
		if err != nil {
			return logs, err
		}
		if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), 0600); err != nil {
			return logs, err
		}
		logs = append(logs, "written: "+csrPath)
	}

	// sign
	if _, err := os.Stat(crtPath); errors.Is(err, os.ErrNotExist) {
		csrData, err := os.ReadFile(csrPath)
		if err != nil {
			return logs, err
		}
		block, _ := pem.Decode(csrData)
		csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return logs, err
		}
		if err := csrParsed.CheckSignature(); err != nil {
			return logs, err
		}
		signParsed, err := readCert(signCertPath)
		if err != nil {
			return logs, err
		}
		signKey, err := readPrivateKey(signKeyPath, signPass)
		if err != nil {
			return logs, fmt.Errorf("could not read signing CA key (wrong passphrase?): %w", err)
		}
		pub, ok := csrParsed.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return logs, errors.New("unsupported CSR key type")
		}
		tmpl := x509.Certificate{
			SerialNumber:          newSerial(),
			Subject:               csrParsed.Subject,
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(certValidity),
			BasicConstraintsValid: true,
			SubjectKeyId:          subjectKeyId(pub),
			AuthorityKeyId:        signParsed.SubjectKeyId,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		}
		if kind == "server" {
			tmpl.DNSNames = csrParsed.DNSNames
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		} else {
			tmpl.EmailAddresses = csrParsed.EmailAddresses
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, signParsed, csrParsed.PublicKey, signKey)
		if err != nil {
			return logs, err
		}
		if err := writePEM(crtPath, "CERTIFICATE", der, &logs); err != nil {
			return logs, err
		}

		// chain: key + cert + intermediate + root
		var chain bytes.Buffer
		for _, p := range []string{keyPath, crtPath, signCertPath, rootCertPath} {
			data, err := os.ReadFile(p)
			if err != nil {
				return logs, err
			}
			chain.Write(data)
		}
		if err := os.WriteFile(chainPath, chain.Bytes(), 0600); err != nil {
			return logs, err
		}
		logs = append(logs, "written: "+chainPath)

		st, err := loadState()
		if err != nil {
			return logs, err
		}
		st.Certs = append(st.Certs, CertRecord{
			Serial:     tmpl.SerialNumber.Text(16),
			Kind:       kind,
			Name:       name,
			CommonName: cn,
			Email:      email,
			NotAfter:   tmpl.NotAfter,
		})
		if err := saveState(st); err != nil {
			return logs, err
		}
	}

	// pkcs12
	if _, err := os.Stat(p12Path); errors.Is(err, os.ErrNotExist) {
		out, err := runOpenSSL(nil,
			map[string]string{envPassP12: p12Pass, envPassName: keyPass},
			"pkcs12", "-export", "-name", name,
			"-in", crtPath, "-inkey", keyPath,
			"-passout", "env:"+envPassP12, "-passin", "env:"+envPassName)
		if err != nil {
			return logs, err
		}
		if err := os.WriteFile(p12Path, out, 0600); err != nil {
			return logs, err
		}
		logs = append(logs, "written: "+p12Path)
	}

	logs = append(logs, "certificate for "+name+" issued")
	return logs, nil
}

func IssueServer(fqdn, signPass, p12Pass string) ([]string, error) {
	if strings.TrimSpace(fqdn) == "" {
		return nil, errors.New("fqdn must not be empty")
	}
	// server keys are unencrypted; keyPass is only used if a matching
	// encrypted key file is present (should not happen)
	return issueCert("server", fqdn, fqdn, "", "", signPass, p12Pass)
}

func IssueUser(cn, email, userPass, signPass, p12Pass string) ([]string, error) {
	if strings.TrimSpace(cn) == "" {
		return nil, errors.New("common name must not be empty")
	}
	if !validEmail(email) {
		return nil, errors.New("email must be in the format name@domain")
	}
	if userPass == "" {
		return nil, errors.New("user passphrase must not be empty")
	}
	return issueCert("user", email, cn, email, userPass, signPass, p12Pass)
}

func validEmail(s string) bool {
	at := strings.Index(s, "@")
	if at <= 0 || strings.Count(s, "@") != 1 {
		return false
	}
	return strings.Contains(s[at+1:], ".") && !strings.ContainsAny(s, " \t")
}

func ListIssued() ([]CertRecord, error) {
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	return st.Certs, nil
}
