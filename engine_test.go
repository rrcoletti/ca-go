package main

import (
  "os"
  "path/filepath"
  "strings"
  "testing"
)

func TestValidName(t *testing.T) {
  good := []string{"host.example.com", "user@example.com", "a-b_c.d"}
  bad := []string{"", "../evil", "a/b", `a\b`, "a b", "a;b", ".", "..", ".hidden"}
  for _, s := range good {
    if !validName(s) {
      t.Errorf("validName(%q) = false, want true", s)
    }
  }
  for _, s := range bad {
    if validName(s) {
      t.Errorf("validName(%q) = true, want false", s)
    }
  }
}

// A traversing fqdn must be rejected before any file is touched.
func TestIssueServerRejectsTraversal(t *testing.T) {
  dir := t.TempDir()
  old := baseDir
  baseDir = dir
  t.Cleanup(func() { baseDir = old })

  if _, err := IssueServer("../../evil", "pw", ""); err == nil {
    t.Fatal("expected error for path-traversing fqdn")
  }
  entries, err := os.ReadDir(dir)
  if err != nil {
    t.Fatal(err)
  }
  if len(entries) != 0 {
    var names []string
    for _, e := range entries {
      names = append(names, e.Name())
    }
    t.Fatalf("expected empty directory, got %v", names)
  }
}

func TestConfRoundTrip(t *testing.T) {
  home := t.TempDir()
  t.Setenv("XDG_CONFIG_HOME", home)
  t.Setenv("HOME", home)

  // no conf file: default dir stays, identity empty
  baseDir = defaultBaseDir()
  if err := loadConf(); err != nil {
    t.Fatal(err)
  }
  if baseDir != filepath.Join(home, "ca-go") {
    t.Fatalf("baseDir = %q, want default ~/ca-go", baseDir)
  }
  if identityConfigured() {
    t.Fatal("identity should be unconfigured without conf file")
  }

  // save, then load back
  orgName, rootCN = "Example", "Example Root CA"
  baseDir = "/data/my-ca"
  if err := saveConf(); err != nil {
    t.Fatal(err)
  }
  orgName, rootCN = "", ""
  baseDir = "/somewhere/else"
  if err := loadConf(); err != nil {
    t.Fatal(err)
  }
  if baseDir != "/data/my-ca" || orgName != "Example" ||
    rootCN != "Example Root CA" {
    t.Fatalf("round trip mismatch: dir=%q org=%q root=%q",
      baseDir, orgName, rootCN)
  }
  if !identityConfigured() {
    t.Fatal("identity should be configured after load")
  }
  p := home + "/ca-go/ca-go.conf"
  if _, err := os.Stat(p); err != nil {
    t.Fatalf("conf file missing: %v", err)
  }
}

// Issuing must refuse when the CA on disk does not match the configured
// identity, and must not create anything. With a consistent identity it
// proceeds normally.
func TestIssueRefusesIdentityMismatch(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }

  orgName = "Someone Else"
  stateBefore, err := os.ReadFile(filepath.Join(baseDir, "state.json"))
  if err != nil {
    t.Fatal(err)
  }
  _, err = IssueServer("host.example.com", "rp", "")
  if err == nil {
    t.Fatal("expected refusal on identity mismatch")
  }
  if !strings.Contains(err.Error(), "does not match ca-go configuration") {
    t.Fatalf("unexpected error: %v", err)
  }
  if _, e := os.Stat(filepath.Join(baseDir, "servers/keys/host.example.com.key")); !os.IsNotExist(e) {
    t.Fatal("server key was created despite refusal")
  }
  stateAfter, err := os.ReadFile(filepath.Join(baseDir, "state.json"))
  if err != nil {
    t.Fatal(err)
  }
  if string(stateBefore) != string(stateAfter) {
    t.Fatal("state was modified despite refusal")
  }

  orgName = "Example"
  if _, err := IssueServer("host.example.com", "rp", ""); err != nil {
    t.Fatalf("issue with consistent identity failed: %v", err)
  }
}

// Issuing without any CA must fail early with a clear message.
func TestIssueWithoutCA(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  _, err := IssueServer("host.example.com", "rp", "")
  if err == nil || !strings.Contains(err.Error(), "no CA exists") {
    t.Fatalf("expected 'no CA exists' error, got: %v", err)
  }
}

// wrapText keeps lines within the width, preserving newlines and short lines.
func TestWrapText(t *testing.T) {
  long := strings.Repeat("word ", 30)
  wrapped := wrapText(long, 40)
  for _, line := range strings.Split(wrapped, "\n") {
    if len(line) > 40 {
      t.Fatalf("line longer than 40: %q", line)
    }
  }
  short := wrapText("hello\nworld", 40)
  if short != "hello\nworld" {
    t.Fatalf("short text mangled: %q", short)
  }
  if got := wrapText("a b c", 80); got != "a b c" {
    t.Fatalf("plain text mangled: %q", got)
  }
}

// A wrong CA passphrase must fail before anything is written, with
// a short user-facing message; full detail goes to logs/ca-go.log.
func TestWrongCAPassWritesNothing(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }

  _, err := IssueServer("host.example.com", "WRONG", "")
  if err == nil {
    t.Fatal("expected wrong-passphrase error")
  }
  if !strings.Contains(err.Error(), "passphrase seems wrong") ||
    strings.Contains(err.Error(), "openssl pkey") {
    t.Fatalf("message should be short and point at the log, got: %v", err)
  }
  if _, e := os.Stat(filepath.Join(baseDir, "servers/keys/host.example.com.key")); !os.IsNotExist(e) {
    t.Fatal("server key was written despite wrong passphrase")
  }
  if _, e := os.Stat(filepath.Join(baseDir, "servers/csrs/host.example.com.csr")); !os.IsNotExist(e) {
    t.Fatal("csr was written despite wrong passphrase")
  }
  logData, err := os.ReadFile(filepath.Join(baseDir, "logs/ca-go.log"))
  if err != nil {
    t.Fatalf("log file missing: %v", err)
  }
  if !strings.Contains(string(logData), "openssl pkey") ||
    !strings.Contains(string(logData), "Could not read key") {
    t.Fatalf("log lacks openssl detail: %s", logData)
  }

  // correct passphrase still issues fine afterwards
  if _, err := IssueServer("host.example.com", "rp", ""); err != nil {
    t.Fatalf("issuance with correct passphrase failed: %v", err)
  }
}

// User emails and common names must be unique among valid certificates;
// revoking frees the identity for reissue.
func TestUserDuplicateGuards(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  if _, err := IssueUser("User Name", "user@example.com", "up", "rp", ""); err != nil {
    t.Fatal(err)
  }

  // same CN (and email): refused, CN reported first
  _, err := IssueUser("User Name", "user@example.com", "up", "rp", "")
  if err == nil || !strings.Contains(err.Error(), "common name") {
    t.Fatalf("expected duplicate-CN refusal, got: %v", err)
  }
  // same email, different CN: refused on the email
  _, err = IssueUser("User Name 2", "user@example.com", "up", "rp", "")
  if err == nil || !strings.Contains(err.Error(), "for user@example.com already exists") {
    t.Fatalf("expected duplicate-email refusal, got: %v", err)
  }

  // revoking renames the artifacts away and frees the identity
  if _, err := Revoke("user", "user@example.com", "rp"); err != nil {
    t.Fatal(err)
  }
  if _, e := os.Stat(filepath.Join(baseDir, "users/certs/user@example.com.crt")); !os.IsNotExist(e) {
    t.Fatal("revoked cert still under its live name")
  }
  checkRevokedArtifacts(t, baseDir, "user@example.com")
  if _, err := IssueUser("User Name", "user@example.com", "up", "rp", ""); err != nil {
    t.Fatalf("reissue after revocation should work: %v", err)
  }
}

// Revoke renames every artifact to *.revoked.<timestamp> with mode 000
// instead of deleting, and a reissue creates fresh files.
func checkRevokedArtifacts(t *testing.T, dir, name string) {
  t.Helper()
  matches, err := filepath.Glob(filepath.Join(dir, "*", "*", name+".*"+".revoked.*"))
  if err != nil {
    t.Fatal(err)
  }
  if len(matches) < 4 { // key, csr, crt, chain (p12 only when exported)
    t.Fatalf("expected renamed artifacts, got %v", matches)
  }
  for _, f := range matches {
    info, err := os.Stat(f)
    if err != nil {
      t.Fatal(err)
    }
    if info.Mode().Perm() != 0000 {
      t.Fatalf("%s has mode %v, want 0000", f, info.Mode().Perm())
    }
    if strings.HasPrefix(info.Name(), name) && !strings.Contains(info.Name(), ".revoked.") {
      t.Fatalf("%s was not renamed", f)
    }
  }
}

// Server FQDNs must be unique among valid certificates; after revocation
// the same FQDN reissues with fresh artifacts.
func TestServerReissueAfterRevocation(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  if _, err := IssueServer("host.example.com", "rp", ""); err != nil {
    t.Fatal(err)
  }
  _, err := IssueServer("host.example.com", "rp", "")
  if err == nil || !strings.Contains(err.Error(), "already exists") {
    t.Fatalf("expected duplicate refusal, got: %v", err)
  }
  if _, err := Revoke("server", "host.example.com", "rp"); err != nil {
    t.Fatal(err)
  }
  checkRevokedArtifacts(t, baseDir, "host.example.com")
  if _, err := IssueServer("host.example.com", "rp", ""); err != nil {
    t.Fatalf("reissue after revocation should work: %v", err)
  }
  // state keeps the revoked record and adds the new one
  recs, err := ListIssued()
  if err != nil {
    t.Fatal(err)
  }
  found := map[bool]int{}
  for _, r := range recs {
    if r.Name == "host.example.com" {
      found[r.Revoked]++
    }
  }
  if found[true] != 1 || found[false] != 1 {
    t.Fatalf("expected one revoked and one valid record, got %v", found)
  }
  // revoking the reissued cert must work too, despite the older revoked
  // record for the same FQDN
  if _, err := Revoke("server", "host.example.com", "rp"); err != nil {
    t.Fatalf("second revocation failed: %v", err)
  }
  recs, err = ListIssued()
  if err != nil {
    t.Fatal(err)
  }
  found = map[bool]int{}
  for _, r := range recs {
    if r.Name == "host.example.com" {
      found[r.Revoked]++
    }
  }
  if found[true] != 2 || found[false] != 0 {
    t.Fatalf("expected two revoked records, got %v", found)
  }
}

// Serial hex is zero-padded on write and tolerates legacy odd-length
// values on read.
func TestParseSerialHex(t *testing.T) {
  for _, s := range []string{"abc", "0abc", "77a2ee5ca8c2c6bac993436b05e0f849"} {
    n, err := parseSerialHex(s)
    if err != nil {
      t.Fatalf("parseSerialHex(%q): %v", s, err)
    }
    if n.Sign() <= 0 {
      t.Fatalf("parseSerialHex(%q) = %v, want positive", s, n)
    }
  }
  if _, err := parseSerialHex("zz"); err == nil {
    t.Fatal("expected error for non-hex serial")
  }
}

// Success messages are one line plus the log pointer; details live in
// logs/ca-go.log.
func TestShortSuccessMessages(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  want := []string{"CA created", "", "See 'logs/ca-go.log' in the CA directory for details"}
  lines, err := NewCA("rp")
  if err != nil {
    t.Fatal(err)
  }
  if strings.Join(lines, "|") != strings.Join(want, "|") {
    t.Fatalf("NewCA lines = %q, want %q", lines, want)
  }

  want = []string{"certificate for host.example.com issued", "", "See 'logs/ca-go.log' in the CA directory for details"}
  lines, err = IssueServer("host.example.com", "rp", "")
  if err != nil {
    t.Fatal(err)
  }
  if strings.Join(lines, "|") != strings.Join(want, "|") {
    t.Fatalf("IssueServer lines = %q, want %q", lines, want)
  }

  want = []string{"certificate for user@example.com issued", "", "See 'logs/ca-go.log' in the CA directory for details"}
  lines, err = IssueUser("User Name", "user@example.com", "up", "rp", "")
  if err != nil {
    t.Fatal(err)
  }
  if strings.Join(lines, "|") != strings.Join(want, "|") {
    t.Fatalf("IssueUser lines = %q, want %q", lines, want)
  }

  want = []string{"CRL regenerated", "", "See 'logs/ca-go.log' in the CA directory for details"}
  lines, err = RegenerateCRL("rp")
  if err != nil {
    t.Fatal(err)
  }
  if strings.Join(lines, "|") != strings.Join(want, "|") {
    t.Fatalf("RegenerateCRL lines = %q, want %q", lines, want)
  }
}

// Revoking or regenerating the CRL without a CA must fail with the
// friendly message (not a raw os error) and must not create anything.
func TestRevokeAndCRLWithoutCA(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  _, err := Revoke("server", "host.example.com", "rp")
  if err == nil || !strings.Contains(err.Error(), "no CA exists") {
    t.Fatalf("expected 'no CA exists' error, got: %v", err)
  }
  _, err = RegenerateCRL("rp")
  if err == nil || !strings.Contains(err.Error(), "no CA exists") {
    t.Fatalf("expected 'no CA exists' error, got: %v", err)
  }
  entries, err := os.ReadDir(baseDir)
  if err != nil {
    t.Fatal(err)
  }
  if len(entries) != 0 {
    var names []string
    for _, e := range entries {
      names = append(names, e.Name())
    }
    t.Fatalf("failing calls must not create anything, got %v", names)
  }
}

// Consistency rule: a conf that disagrees with the CA on disk blocks
// revocation and CRL regeneration, exactly like issuance. The refusal
// happens before anything is written.
func TestRevokeAndCRLRefuseIdentityMismatch(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  stateBefore, err := os.ReadFile(filepath.Join(baseDir, "state.json"))
  if err != nil {
    t.Fatal(err)
  }

  orgName = "Someone Else"
  _, err = Revoke("server", "host.example.com", "rp")
  if err == nil || !strings.Contains(err.Error(), "cannot revoke the certificate") ||
    !strings.Contains(err.Error(), "does not match ca-go configuration") {
    t.Fatalf("expected revoke refusal, got: %v", err)
  }
  _, err = RegenerateCRL("rp")
  if err == nil || !strings.Contains(err.Error(), "cannot regenerate the CRL") ||
    !strings.Contains(err.Error(), "does not match ca-go configuration") {
    t.Fatalf("expected CRL refusal, got: %v", err)
  }

  stateAfter, err := os.ReadFile(filepath.Join(baseDir, "state.json"))
  if err != nil {
    t.Fatal(err)
  }
  if string(stateBefore) != string(stateAfter) {
    t.Fatal("state was modified despite refusal")
  }
}

// Clients match hostnames against the SAN, not the CN (CN is ignored),
// so a server certificate must carry DNS:<fqdn> as subjectAltName.
func TestServerCertHasSAN(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  if _, err := IssueServer("host.example.com", "rp", ""); err != nil {
    t.Fatal(err)
  }
  cert, err := readCert(filepath.Join(baseDir, "servers/certs/host.example.com.crt"))
  if err != nil {
    t.Fatal(err)
  }
  if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "host.example.com" {
    t.Fatalf("expected SAN DNS:host.example.com, got %v", cert.DNSNames)
  }
}

// S/MIME clients match on the email SAN, so a user certificate must
// carry RFC822:<email> as subjectAltName.
func TestUserCertHasEmailSAN(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  if _, err := IssueUser("User Name", "user@example.com", "up", "rp", ""); err != nil {
    t.Fatal(err)
  }
  cert, err := readCert(filepath.Join(baseDir, "users/certs/user@example.com.crt"))
  if err != nil {
    t.Fatal(err)
  }
  if len(cert.EmailAddresses) != 1 || cert.EmailAddresses[0] != "user@example.com" {
    t.Fatalf("expected SAN email:user@example.com, got %v", cert.EmailAddresses)
  }
}
