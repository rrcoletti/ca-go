// ca-go - private CA manager.
// Copyright (C) 2026 Rafael Coletti
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "math/big"
  "os"
  "os/exec"
  "path/filepath"
  "strings"
  "testing"
  "time"
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

  if _, err := IssueServer("../../evil", "", "pw", ""); err == nil {
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

// An inline comment after a value is stripped before the value is
// used, so "dir = /x # note" yields "/x". The cut happens at the
// first '#', with or without whitespace before it.
func TestLoadConfInlineComment(t *testing.T) {
  home := t.TempDir()
  t.Setenv("XDG_CONFIG_HOME", home)
  t.Setenv("HOME", home)
  dir := home + "/ca-go"
  if err := os.MkdirAll(dir, 0700); err != nil {
    t.Fatal(err)
  }
  conf := dir + "/ca-go.conf"
  content := "# ca-go configuration\n" +
    "dir = /data/my-ca # moved after the SSD reorg\n" +
    "org = Example#tight\n" +
    "rootCN = Example Root CA\n"
  if err := os.WriteFile(conf, []byte(content), 0600); err != nil {
    t.Fatal(err)
  }

  oldBase, oldOrg, oldCN := baseDir, orgName, rootCN
  t.Cleanup(func() { baseDir, orgName, rootCN = oldBase, oldOrg, oldCN })

  baseDir, orgName, rootCN = defaultBaseDir(), "", ""
  if err := loadConf(); err != nil {
    t.Fatal(err)
  }
  if baseDir != "/data/my-ca" {
    t.Fatalf("dir = %q, want /data/my-ca (comment stripped)", baseDir)
  }
  if orgName != "Example" {
    t.Fatalf("org = %q, want Example (comment stripped even without space)", orgName)
  }
  if rootCN != "Example Root CA" {
    t.Fatalf("rootCN = %q, want Example Root CA", rootCN)
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
  _, err = IssueServer("host.example.com", "", "rp", "")
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
  if _, err := IssueServer("host.example.com", "", "rp", ""); err != nil {
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

  _, err := IssueServer("host.example.com", "", "rp", "")
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

  _, err := IssueServer("host.example.com", "", "WRONG", "")
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
  if _, err := IssueServer("host.example.com", "", "rp", ""); err != nil {
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
  if _, err := IssueServer("host.example.com", "", "rp", ""); err != nil {
    t.Fatal(err)
  }
  _, err := IssueServer("host.example.com", "", "rp", "")
  if err == nil || !strings.Contains(err.Error(), "already exists") {
    t.Fatalf("expected duplicate refusal, got: %v", err)
  }
  if _, err := Revoke("server", "host.example.com", "rp"); err != nil {
    t.Fatal(err)
  }
  checkRevokedArtifacts(t, baseDir, "host.example.com")
  if _, err := IssueServer("host.example.com", "", "rp", ""); err != nil {
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
  lines, err = IssueServer("host.example.com", "", "rp", "")
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
  if _, err := IssueServer("host.example.com", "", "rp", ""); err != nil {
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

// A half-created CA (leftover key without a certificate) must be
// rejected with a manual-cleanup hint, not silently overwritten.
func TestHalfCreatedCARejected(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if err := os.MkdirAll(filepath.Join(baseDir, "ca-root/keys"), 0700); err != nil {
    t.Fatal(err)
  }
  if err := os.WriteFile(rootKeyPath(), []byte("junk"), 0600); err != nil {
    t.Fatal(err)
  }
  _, err := NewCA("rp")
  if err == nil {
    t.Fatal("expected half-created CA error")
  }
  if !strings.Contains(err.Error(), "half-created CA files") ||
    !strings.Contains(err.Error(), rootKeyPath()) {
    t.Fatalf("expected manual-cleanup error listing the leftover file, got: %v", err)
  }
  if _, e := os.Stat(rootKeyPath()); e != nil {
    t.Fatal("leftover key was removed implicitly")
  }
}

// A half-created certificate (leftover key without a certificate) must
// be rejected with a manual-cleanup hint, not cleaned up implicitly.
func TestHalfCreatedCertRejected(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  keyPath := filepath.Join(baseDir, "servers/keys/host.example.com.key")
  if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
    t.Fatal(err)
  }
  if err := os.WriteFile(keyPath, []byte("junk"), 0600); err != nil {
    t.Fatal(err)
  }
  _, err := IssueServer("host.example.com", "", "rp", "")
  if err == nil {
    t.Fatal("expected half-created certificate error")
  }
  if !strings.Contains(err.Error(), "half-created certificate files") ||
    !strings.Contains(err.Error(), keyPath) {
    t.Fatalf("expected manual-cleanup error listing the leftover file, got: %v", err)
  }
  if _, e := os.Stat(keyPath); e != nil {
    t.Fatal("leftover key was removed implicitly")
  }
}

// Losing state.json must not reset the CRL number: the next CRL is
// seeded from the number of the existing CRL file.
func TestCRLNumberNeverGoesBackwards(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  if _, err := RegenerateCRL("rp"); err != nil {
    t.Fatal(err)
  }
  before, err := readCRLNumber(rootCrlPath())
  if err != nil {
    t.Fatal(err)
  }
  if before != 2 {
    t.Fatalf("expected CRL number 2 after one regeneration, got %d", before)
  }

  if err := os.Remove(statePath()); err != nil {
    t.Fatal(err)
  }
  if _, err := RegenerateCRL("rp"); err != nil {
    t.Fatal(err)
  }
  after, err := readCRLNumber(rootCrlPath())
  if err != nil {
    t.Fatal(err)
  }
  if after != before+1 {
    t.Fatalf("CRL number went backwards after state loss: before=%d after=%d", before, after)
  }
}

// Rows longer than the FQDN/email column are truncated with a visible
// ellipsis, keeping the table aligned.
func TestFormatRecordTruncatesLongName(t *testing.T) {
  long := "subdomain.example-with-a-very-long-name.example.com" // > 20 chars
  row := formatRecord(CertRecord{Kind: "server", Name: long, CommonName: long}, 0)
  if !strings.Contains(row, "subdomain.example-w…") {
    t.Fatalf("expected truncated name with ellipsis, got: %q", row)
  }
  short := formatRecord(CertRecord{Kind: "server", Name: "host.example.com", CommonName: "host.example.com"}, 0)
  if !strings.Contains(short, "host.example.com ") {
    t.Fatalf("short names must not be truncated, got: %q", short)
  }
}

func runeSliceIndex(haystack, needle []rune) int {
  for i := 0; i+len(needle) <= len(haystack); i++ {
    match := true
    for j, rn := range needle {
      if haystack[i+j] != rn {
        match = false
        break
      }
    }
    if match {
      return i
    }
  }
  return -1
}

// The name columns split the terminal width 50/50 after the fixed
// columns; both header and rows share the widths, so the table stays
// aligned at any size. Width 0 keeps the classic 28/20 layout.
func TestRecordWidthsFollowTerminal(t *testing.T) {
  r := CertRecord{
    Kind: "server", Name: "host.example.com", CommonName: "host.example.com",
    NotAfter: time.Date(2028, 9, 4, 0, 0, 0, 0, time.UTC),
  }
  for _, w := range []int{0, 60, 80, 120, 20} {
    row := formatRecord(r, w)
    header := formatRecordHeader(w)
    // the date column must start at the same rune offset in header and
    // row; only the trailing Status/Valid token may differ in length
    hr, rr := []rune(header), []rune(row)
    if runeSliceIndex(hr, []rune("Expires")) != runeSliceIndex(rr, []rune("2028-09-04")) {
      t.Fatalf("width %d: date column misaligned:\n%q\n%q", w, header, row)
    }
    if w == 0 {
      if !strings.Contains(header, "Common Name (CN)      ") {
        t.Fatalf("width 0 must keep the classic 28-wide CN column: %q", header)
      }
      continue
    }
    cnW, fqdnW := recordWidths(w)
    // names at or under the column width must appear untruncated and
    // left-justified, so the next column starts exactly where the
    // header's does
    if cnW >= len(r.CommonName) && !strings.HasPrefix(row[len(r.Kind)+1:], r.CommonName) {
      t.Fatalf("width %d: CN column misaligned: %q", w, row)
    }
    if cnW < 8 || fqdnW < 8 {
      t.Fatalf("width %d: columns below the floor: %d/%d", w, cnW, fqdnW)
    }
  }
}

// The status column reflects validity: revoked certificates show
// REVOKED, expired ones EXPIRED, and valid ones inside the warning
// window EXPIRING; everything else stays Valid. The boundary is
// inclusive: a certificate expiring exactly 30 days out counts as
// expiring.
func TestRecordStatus(t *testing.T) {
  now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
  cases := []struct {
    name string
    rec  CertRecord
    want string
  }{
    {"valid", CertRecord{NotAfter: now.Add(400 * 24 * time.Hour)}, "Valid"},
    {"just over the window", CertRecord{NotAfter: now.Add(30*24*time.Hour + time.Minute)}, "Valid"},
    {"exactly 30 days out", CertRecord{NotAfter: now.Add(30 * 24 * time.Hour)}, "EXPIRING"},
    {"tomorrow", CertRecord{NotAfter: now.Add(24 * time.Hour)}, "EXPIRING"},
    {"expired", CertRecord{NotAfter: now.Add(-time.Minute)}, "EXPIRED"},
    {"revoked overrides everything", CertRecord{NotAfter: now.Add(-time.Minute), Revoked: true}, "REVOKED"},
    {"revoked but still valid", CertRecord{NotAfter: now.Add(400 * 24 * time.Hour), Revoked: true}, "REVOKED"},
  }
  for _, c := range cases {
    if got := recordStatus(c.rec, now); got != c.want {
      t.Errorf("%s: got %q, want %q", c.name, got, c.want)
    }
  }
}

// formatRecord renders the derived statuses so the show screens flag
// expiring and expired certificates in the table itself.
func TestFormatRecordShowsExpiryStatus(t *testing.T) {
  soon := time.Now().Add(10 * 24 * time.Hour)
  past := time.Now().Add(-24 * time.Hour)
  if row := formatRecord(CertRecord{Kind: "server", Name: "h", CommonName: "h", NotAfter: soon}, 0); !strings.Contains(row, "EXPIRING") {
    t.Fatalf("expected EXPIRING in row, got %q", row)
  }
  if row := formatRecord(CertRecord{Kind: "server", Name: "h", CommonName: "h", NotAfter: past}, 0); !strings.Contains(row, "EXPIRED") {
    t.Fatalf("expected EXPIRED in row, got %q", row)
  }
}

// ExpiryNotes distinguishes severity by prefix: expiring certificates
// yield EXPIRING lines, expired ones EXPIRED, ignoring revoked ones;
// a stale CRL is also EXPIRED.
func TestExpiryNotes(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })

  now := time.Now()
  recs := []CertRecord{
    {Kind: "server", Name: "fresh", NotAfter: now.Add(400 * 24 * time.Hour)},
    {Name: "gone", NotAfter: now.Add(-time.Hour), Revoked: true},
  }
  if notes := ExpiryNotes(recs); len(notes) != 0 {
    t.Fatalf("healthy CA with fresh CRL must be silent, got %q", notes)
  }

  recs = []CertRecord{
    {Name: "a", NotAfter: now.Add(10 * 24 * time.Hour)},
    {Name: "b", NotAfter: now.Add(-time.Hour)},
    {Name: "c", NotAfter: now.Add(-2 * time.Hour), Revoked: true},
  }
  notes := ExpiryNotes(recs)
  if len(notes) != 2 {
    t.Fatalf("expected expiring + expired notes, got %q", notes)
  }
  if !strings.Contains(notes[0], "EXPIRED: 1 certificate(s) expired") || !strings.Contains(notes[1], "EXPIRING: 1 certificate(s) expire within 30 days") {
    t.Fatalf("unexpected note wording: %q", notes)
  }

  // a CRL whose NextUpdate date has passed adds the regenerate note
  if err := os.MkdirAll(filepath.Dir(rootCrlPath()), 0700); err != nil {
    t.Fatal(err)
  }
  if err := os.WriteFile(rootCrlPath(), staleCRL(t), 0600); err != nil {
    t.Fatal(err)
  }
  notes = ExpiryNotes(nil)
  if len(notes) != 1 || !strings.Contains(notes[0], "EXPIRED: the CRL") {
    t.Fatalf("expected only the CRL notice, got %q", notes)
  }
}

// staleCRL builds a signed CRL whose NextUpdate date is in the past,
// signed by a throwaway self-signed CA, for crlStale() tests.
func staleCRL(t *testing.T) []byte {
  t.Helper()
  key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    t.Fatal(err)
  }
  tmpl := &x509.Certificate{
    SerialNumber: big.NewInt(1),
    Subject:      pkix.Name{CommonName: "stale test CA"},
    NotBefore:    time.Now().Add(-24 * time.Hour),
    NotAfter:     time.Now().Add(24 * time.Hour),
    KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
    IsCA:         true,
    BasicConstraintsValid: true,
  }
  der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
  if err != nil {
    t.Fatal(err)
  }
  ca, err := x509.ParseCertificate(der)
  if err != nil {
    t.Fatal(err)
  }
  rlDer, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
    Number:     big.NewInt(1),
    ThisUpdate: time.Now().Add(-2 * time.Hour),
    NextUpdate: time.Now().Add(-time.Hour),
  }, ca, key)
  if err != nil {
    t.Fatal(err)
  }
  return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rlDer})
}

// The encrypted key must carry a strong PBKDF2 iteration count; the
// openssl default is only 2048.
func TestEncryptedKeyUsesHighKDFIterations(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })

  key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    t.Fatal(err)
  }
  path := filepath.Join(baseDir, "k.key")
  var detail []string
  if err := writeEncryptedKey(key, path, "up", envUserPass, &detail); err != nil {
    t.Fatal(err)
  }
  out, err := exec.Command("openssl", "asn1parse", "-in", path).Output()
  if err != nil {
    t.Fatal(err)
  }
  // 600000 = 0x927C0; the openssl default would be 0x0800 (2048)
  if !strings.Contains(string(out), ":0927C0") {
    t.Fatalf("expected PBKDF2 iteration count 600000 (0x927C0), got:\n%s", out)
  }
  // and the key must still be readable with its passphrase
  if _, err := readPrivateKey(path, "up", envUserPass); err != nil {
    t.Fatalf("encrypted key unreadable after hardening: %v", err)
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

// A server key passphrase is optional: non-empty encrypts the key like
// a user key (and feeds the p12 export); empty keeps the plain key.
func TestServerKeyOptionalPassphrase(t *testing.T) {
  chdirCA(t)
  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }

  lines, err := IssueServer("enc.example.com", "skp", "rp", "p12p")
  if err != nil {
    t.Fatalf("issue with encrypted key: %v\n%s", err, strings.Join(lines, "\n"))
  }
  encPath := caPath("servers/keys/enc.example.com.key")
  encPEM, err := os.ReadFile(encPath)
  if err != nil {
    t.Fatal(err)
  }
  if !strings.Contains(string(encPEM), "ENCRYPTED PRIVATE KEY") {
    t.Fatal("expected an encrypted server key PEM")
  }
  if _, err := readPrivateKey(encPath, "skp", envServerPass); err != nil {
    t.Fatalf("encrypted server key must open with its passphrase: %v", err)
  }
  for _, f := range []string{
    caPath("servers/certs/enc.example.com.crt"),
    caPath("servers/certs/enc.example.com-chain.pem"),
    caPath("servers/p12/enc.example.com.p12"),
  } {
    if ok, err := exists(f); err != nil || !ok {
      t.Fatalf("missing artifact %s", f)
    }
  }

  if _, err := IssueServer("plain.example.com", "", "rp", "p12p"); err != nil {
    t.Fatalf("issue with unencrypted key: %v", err)
  }
  plainPEM, err := os.ReadFile(caPath("servers/keys/plain.example.com.key"))
  if err != nil {
    t.Fatal(err)
  }
  if !strings.Contains(string(plainPEM), "PRIVATE KEY") || strings.Contains(string(plainPEM), "ENCRYPTED") {
    t.Fatal("expected an unencrypted server key PEM")
  }
}
