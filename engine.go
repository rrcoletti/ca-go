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
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// baseDir is the root of the CA tree. Defaults to ~/ca-go and can be
// overridden via ~/.config/ca-go/ca-go.conf (dir = /some/path).
var baseDir = defaultBaseDir()

// Identity used in certificate subjects. Empty until loaded from the
// conf file or entered on first run.
var (
  orgName  string
  rootCN   string
  signCN   string
)

func defaultBaseDir() string {
  home, err := os.UserHomeDir()
  if err != nil || home == "" {
    return "ca-go"
  }
  return filepath.Join(home, "ca-go")
}

func caPath(rel string) string { return filepath.Join(baseDir, rel) }

func rootKeyPath() string   { return caPath("ca-root/keys/root-ca.key") }
func rootCertPath() string  { return caPath("ca-root/certs/root-ca.crt") }
func rootCrlPath() string   { return caPath("ca-root/crls/root-ca.crl") }
func signKeyPath() string   { return caPath("ca-sign/keys/sign-ca.key") }
func signCertPath() string  { return caPath("ca-sign/certs/sign-ca.crt") }
func signCrlPath() string   { return caPath("ca-sign/crls/sign-ca.crl") }
func signChainPath() string { return caPath("ca-sign/certs/ca-chain.pem") }
func statePath() string     { return caPath("state.json") }
func stateLockPath() string { return caPath("state.lock") }

const (
  certValidity  = 730 * 24 * time.Hour
  caValidity    = 10 * 365 * 24 * time.Hour
  signCrlWindow = 90 * 24 * time.Hour
  rootCrlWindow = 365 * 24 * time.Hour
  envRootPass   = "CAGO_ROOT_PASS"
  envSignPass   = "CAGO_SIGN_PASS"
  envUserPass   = "CAGO_USER_PASS"
  envP12Pass    = "CAGO_P12_PASS"
)

// identityConfigured reports whether the naming conf entries are present.
func identityConfigured() bool {
  return orgName != "" && rootCN != "" && signCN != ""
}

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
  data, err := os.ReadFile(statePath())
  if errors.Is(err, os.ErrNotExist) {
    return st, nil
  }
  if err != nil {
    return nil, err
  }
  if err := json.Unmarshal(data, st); err != nil {
    return nil, fmt.Errorf("corrupt %s: %w", statePath(), err)
  }
  return st, nil
}

func saveState(st *State) error {
  data, err := json.MarshalIndent(st, "", "  ")
  if err != nil {
    return err
  }
  // write to a temp file and rename: a crash mid-write cannot leave a
  // truncated state.json behind
  tmp := statePath() + ".tmp"
  if err := os.WriteFile(tmp, data, 0600); err != nil {
    return err
  }
  return os.Rename(tmp, statePath())
}

// confPath returns ~/.config/ca-go/ca-go.conf.
func confPath() (string, error) {
  cfg, err := os.UserConfigDir()
  if err != nil {
    return "", err
  }
  return filepath.Join(cfg, "ca-go", "ca-go.conf"), nil
}

// loadConf reads the optional config file; unknown keys are ignored.
func loadConf() error {
  p, err := confPath()
  if err != nil {
    return err
  }
  data, err := os.ReadFile(p)
  if errors.Is(err, os.ErrNotExist) {
    return nil
  }
  if err != nil {
    return err
  }
  for _, line := range strings.Split(string(data), "\n") {
    line = strings.TrimSpace(line)
    if line == "" || strings.HasPrefix(line, "#") {
      continue
    }
    k, v, ok := strings.Cut(line, "=")
    if !ok {
      continue
    }
    v = strings.TrimSpace(v)
    if v == "" {
      continue
    }
    switch strings.TrimSpace(k) {
    case "dir":
      baseDir = v
    case "org":
      orgName = v
    case "rootCN":
      rootCN = v
    case "signCN":
      signCN = v
    }
  }
  return nil
}

// saveConf persists all settings.
func saveConf() error {
  p, err := confPath()
  if err != nil {
    return err
  }
  if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
    return err
  }
  content := "# ca-go configuration\n" +
    "dir = " + baseDir + "\n" +
    "org = " + orgName + "\n" +
    "rootCN = " + rootCN + "\n" +
    "signCN = " + signCN + "\n"
  return os.WriteFile(p, []byte(content), 0600)
}

// exists reports whether path is present. Errors other than "not exist"
// (permissions, ...) are propagated instead of being read as "missing".
func exists(path string) (bool, error) {
  _, err := os.Stat(path)
  if err == nil {
    return true, nil
  }
  if errors.Is(err, os.ErrNotExist) {
    return false, nil
  }
  return false, err
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
    if err := os.MkdirAll(caPath(d), 0700); err != nil {
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

// encryptKey returns an EC private key as passphrase-encrypted PKCS#8
// (AES-256) via the openssl CLI. envName selects the password env var.
func encryptKey(key *ecdsa.PrivateKey, pass, envName string) ([]byte, error) {
  der, err := x509.MarshalPKCS8PrivateKey(key)
  if err != nil {
    return nil, err
  }
  pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
  return runOpenSSL(pemBytes, map[string]string{envName: pass},
    "pkcs8", "-topk8", "-v2", "aes256", "-inform", "pem",
    "-passout", "env:"+envName)
}

// writeEncryptedKey encrypts and writes the key.
func writeEncryptedKey(key *ecdsa.PrivateKey, path, pass, envName string, logs *[]string) error {
  out, err := encryptKey(key, pass, envName)
  if err != nil {
    return err
  }
  *logs = append(*logs, "key written: "+path)
  return os.WriteFile(path, out, 0600)
}

// readPrivateKey loads a (possibly encrypted) PKCS#8 key file. envName
// selects the password env var passed to openssl.
func readPrivateKey(path, pass, envName string) (crypto.Signer, error) {
  data, err := os.ReadFile(path)
  if err != nil {
    return nil, err
  }
  out, err := runOpenSSL(data, map[string]string{envName: pass},
    "pkey", "-passin", "env:"+envName)
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

func newSerial() (*big.Int, error) {
  return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// subjectKeyId derives the key identifier per RFC 5280 4.2.1.2:
// SHA-1 over the public key BIT STRING, not the whole SPKI structure.
func subjectKeyId(pub *ecdsa.PublicKey) []byte {
  der, err := x509.MarshalPKIXPublicKey(pub)
  if err != nil {
    panic(err)
  }
  var spki struct {
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
  }
  if _, err := asn1.Unmarshal(der, &spki); err != nil {
    panic(err)
  }
  sum := sha1.Sum(spki.PublicKey.RightAlign())
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

// NewCA creates the root and intermediate CAs. All keys, certificates
// and CRLs are computed before the first file is written, so a failure
// part-way cannot leave a half-created CA behind.
func NewCA(rootPass, signPass string) ([]string, error) {
  logs := []string{}
  if !identityConfigured() {
    return logs, errors.New("identity not configured; run the TUI once to set it up, or fill in org/rootCN/signCN in ~/.config/ca-go/ca-go.conf")
  }
  rootExists, err := exists(rootCertPath())
  if err != nil {
    return logs, err
  }
  signExists, err := exists(signCertPath())
  if err != nil {
    return logs, err
  }
  if rootExists || signExists {
    if rootExists != signExists {
      return logs, errors.New("partial CA exists in this directory; remove the ca-root and ca-sign directories and re-run")
    }
    return logs, errors.New("CA already exists in this directory")
  }
  if rootPass == "" || signPass == "" {
    return logs, errors.New("passphrases must not be empty")
  }

  rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    return logs, err
  }
  rootSerial, err := newSerial()
  if err != nil {
    return logs, err
  }
  rootTmpl := &x509.Certificate{
    SerialNumber:          rootSerial,
    Subject:               pkix.Name{Organization: []string{orgName}, CommonName: rootCN},
    NotBefore:             time.Now().Add(-time.Hour),
    NotAfter:              time.Now().Add(caValidity),
    KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
    BasicConstraintsValid: true,
    IsCA:                  true,
    MaxPathLen:            -1, // no pathLen limit on the root
    SignatureAlgorithm:    x509.ECDSAWithSHA256,
  }
  rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
  if err != nil {
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
  signSerial, err := newSerial()
  if err != nil {
    return logs, err
  }
  signTmpl := &x509.Certificate{
    SerialNumber:          signSerial,
    Subject:               pkix.Name{Organization: []string{orgName}, CommonName: signCN},
    NotBefore:             rootTmpl.NotBefore,
    NotAfter:              rootTmpl.NotAfter,
    KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
    BasicConstraintsValid: true,
    IsCA:                  true,
    MaxPathLen:            0, // pathLen:0 - cannot sign further CAs
    AuthorityKeyId:        rootParsed.SubjectKeyId,
    SignatureAlgorithm:    x509.ECDSAWithSHA256,
  }
  signDER, err := x509.CreateCertificate(rand.Reader, signTmpl, rootParsed, &signKey.PublicKey, rootKey)
  if err != nil {
    return logs, err
  }
  signParsed, err := x509.ParseCertificate(signDER)
  if err != nil {
    return logs, err
  }

  rootEnc, err := encryptKey(rootKey, rootPass, envRootPass)
  if err != nil {
    return logs, err
  }
  signEnc, err := encryptKey(signKey, signPass, envSignPass)
  if err != nil {
    return logs, err
  }

  // CA chain: intermediate + root
  chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signDER})
  chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)

  // empty CRLs for both CAs
  rootCrlDER, err := x509.CreateRevocationList(rand.Reader,
    &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(rootCrlWindow)},
    rootParsed, rootKey)
  if err != nil {
    return logs, err
  }
  st := &State{CRLNumber: 1}
  signCrlDER, err := generateSignCRL(st, signParsed, signKey)
  if err != nil {
    return logs, err
  }

  if err := ensureDirs(); err != nil {
    return logs, err
  }
  writes := []struct {
    path string
    data []byte
  }{
    {rootKeyPath(), rootEnc},
    {rootCertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})},
    {signKeyPath(), signEnc},
    {signCertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signDER})},
    {signChainPath(), chain},
    {rootCrlPath(), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rootCrlDER})},
    {signCrlPath(), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: signCrlDER})},
  }
  for _, w := range writes {
    if err := os.WriteFile(w.path, w.data, 0600); err != nil {
      return logs, err
    }
    logs = append(logs, "written: "+w.path)
  }
  if err := saveState(st); err != nil {
    return logs, err
  }
  logs = append(logs, "CA created")
  return logs, nil
}

// generateSignCRL builds the signing CA's CRL DER from st. Callers are
// responsible for bumping and persisting CRLNumber beforehand.
func generateSignCRL(st *State, signParsed *x509.Certificate, signKey crypto.Signer) ([]byte, error) {
  entries := []x509.RevocationListEntry{}
  for _, c := range st.Certs {
    if !c.Revoked {
      continue
    }
    raw, err := hex.DecodeString(c.Serial)
    if err != nil {
      return nil, err
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
  return x509.CreateRevocationList(rand.Reader, tmpl, signParsed, signKey)
}

func RegenerateCRL(signPass string) ([]string, error) {
  logs := []string{}
  if err := ensureDirs(); err != nil {
    return logs, err
  }
  signParsed, err := readCert(signCertPath())
  if err != nil {
    return logs, err
  }
  signKey, err := readPrivateKey(signKeyPath(), signPass, envSignPass)
  if err != nil {
    return logs, fmt.Errorf("could not read signing CA key (wrong passphrase?): %w", err)
  }
  lk, err := lockState()
  if err != nil {
    return logs, err
  }
  defer unlockState(lk)
  st, err := loadState()
  if err != nil {
    return logs, err
  }
  st.CRLNumber++
  // persist the bumped number even if the CRL step fails, so the
  // number can never go backwards
  if err := saveState(st); err != nil {
    return logs, err
  }
  der, err := generateSignCRL(st, signParsed, signKey)
  if err != nil {
    return logs, err
  }
  if err := writePEM(signCrlPath(), "X509 CRL", der, &logs); err != nil {
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
  signParsed, err := readCert(signCertPath())
  if err != nil {
    return logs, err
  }
  signKey, err := readPrivateKey(signKeyPath(), signPass, envSignPass)
  if err != nil {
    return logs, fmt.Errorf("could not read signing CA key (wrong passphrase?): %w", err)
  }
  lk, err := lockState()
  if err != nil {
    return logs, err
  }
  defer unlockState(lk)
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

  // state is saved before the CRL: if the CRL step fails, the
  // revocation is still recorded and a later `crl` run picks it up
  st.CRLNumber++
  if err := saveState(st); err != nil {
    return logs, err
  }
  der, err := generateSignCRL(st, signParsed, signKey)
  if err != nil {
    return logs, fmt.Errorf("certificate marked revoked in %s, but the CRL update failed (re-run 'crl'): %w", statePath(), err)
  }
  if err := writePEM(signCrlPath(), "X509 CRL", der, &logs); err != nil {
    return logs, fmt.Errorf("certificate marked revoked in %s, but the CRL could not be written (re-run 'crl'): %w", statePath(), err)
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
  // hold the state lock for the whole issuance so two concurrent
  // calls cannot both pass the existence checks or double-append
  lk, err := lockState()
  if err != nil {
    return logs, err
  }
  defer unlockState(lk)
  kindDir := "servers"
  if kind == "user" {
    kindDir = "users"
  }
  keyPath := caPath(kindDir + "/keys/" + name + ".key")
  csrPath := caPath(kindDir + "/csrs/" + name + ".csr")
  crtPath := caPath(kindDir + "/certs/" + name + ".crt")
  chainPath := caPath(kindDir + "/certs/" + name + "-chain.pem")
  p12Path := caPath(kindDir + "/p12/" + name + ".p12")

  keyOK, err := exists(keyPath)
  if err != nil {
    return logs, err
  }
  csrOK, err := exists(csrPath)
  if err != nil {
    return logs, err
  }
  crtOK, err := exists(crtPath)
  if err != nil {
    return logs, err
  }
  // broken state: without the key, the other artifacts are useless;
  // without the cert, chain and p12 are stale.
  if !keyOK {
    for _, f := range []string{csrPath, crtPath, chainPath, p12Path} {
      ok, err := exists(f)
      if err != nil {
        return logs, err
      }
      if ok {
        _ = os.Remove(f)
        logs = append(logs, "removed "+f+" (no matching key)")
      }
    }
  } else if !crtOK {
    for _, f := range []string{chainPath, p12Path} {
      ok, err := exists(f)
      if err != nil {
        return logs, err
      }
      if ok {
        _ = os.Remove(f)
        logs = append(logs, "removed "+f+" (stale, certificate will be reissued)")
      }
    }
  } else {
    return logs, fmt.Errorf("certificate for %s already exists", name)
  }

  // key
  if !keyOK {
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
      return logs, err
    }
    if kind == "user" {
      if err := writeEncryptedKey(key, keyPath, keyPass, envUserPass, &logs); err != nil {
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
  if !csrOK {
    keyData, err := os.ReadFile(keyPath)
    if err != nil {
      return logs, err
    }
    var keyObj crypto.PrivateKey
    if kind == "user" {
      keyObj, err = readPrivateKey(keyPath, keyPass, envUserPass)
    } else {
      block, _ := pem.Decode(keyData)
      if block == nil {
        return logs, fmt.Errorf("could not decode %s", keyPath)
      }
      keyObj, err = x509.ParsePKCS8PrivateKey(block.Bytes)
    }
    if err != nil {
      return logs, err
    }
    subject := pkix.Name{Organization: []string{orgName}, CommonName: cn}
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
  if !crtOK {
    csrData, err := os.ReadFile(csrPath)
    if err != nil {
      return logs, err
    }
    block, _ := pem.Decode(csrData)
    if block == nil {
      return logs, fmt.Errorf("could not decode %s", csrPath)
    }
    csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
    if err != nil {
      return logs, err
    }
    if err := csrParsed.CheckSignature(); err != nil {
      return logs, err
    }
    signParsed, err := readCert(signCertPath())
    if err != nil {
      return logs, err
    }
    signKey, err := readPrivateKey(signKeyPath(), signPass, envSignPass)
    if err != nil {
      return logs, fmt.Errorf("could not read signing CA key (wrong passphrase?): %w", err)
    }
    pub, ok := csrParsed.PublicKey.(*ecdsa.PublicKey)
    if !ok {
      return logs, errors.New("unsupported CSR key type")
    }
    serial, err := newSerial()
    if err != nil {
      return logs, err
    }
    tmpl := x509.Certificate{
      SerialNumber:          serial,
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
      tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
      tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
    } else {
      tmpl.EmailAddresses = csrParsed.EmailAddresses
      tmpl.KeyUsage = x509.KeyUsageDigitalSignature
      tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth}
    }
    der, err := x509.CreateCertificate(rand.Reader, &tmpl, signParsed, csrParsed.PublicKey, signKey)
    if err != nil {
      return logs, err
    }
    if err := writePEM(crtPath, "CERTIFICATE", der, &logs); err != nil {
      return logs, err
    }

    // chain: leaf + intermediate + root (full chain for servers and
    // appliances that want it); the private key must never end up in a
    // file that gets shared with peers
    var chain bytes.Buffer
    for _, p := range []string{crtPath, signCertPath(), rootCertPath()} {
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
      map[string]string{envP12Pass: p12Pass, envUserPass: keyPass},
      "pkcs12", "-export", "-name", name,
      "-in", crtPath, "-inkey", keyPath,
      "-certfile", signCertPath(),
      "-passout", "env:"+envP12Pass, "-passin", "env:"+envUserPass)
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

// validName guards names that become file names: a strict whitelist
// with no separators and no leading dot, so a crafted FQDN or email
// cannot escape the artifact directories.
func validName(s string) bool {
  if s == "" || strings.ContainsAny(s, `/\\`) || strings.HasPrefix(s, ".") {
    return false
  }
  for _, r := range s {
    ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
      r == '.' || r == '-' || r == '_' || r == '@'
    if !ok {
      return false
    }
  }
  return true
}

func IssueServer(fqdn, signPass, p12Pass string) ([]string, error) {
  if strings.TrimSpace(fqdn) == "" {
    return nil, errors.New("fqdn must not be empty")
  }
  if !validName(fqdn) {
    return nil, errors.New("fqdn must only contain letters, digits, '.', '-' and '_'")
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
    return nil, errors.New("email must be in the format name@example.com")
  }
  if userPass == "" {
    return nil, errors.New("user passphrase must not be empty")
  }
  if !validName(email) {
    return nil, errors.New("email contains characters not allowed in file names (letters, digits, '.', '-', '_', '@')")
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
