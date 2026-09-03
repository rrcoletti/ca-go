package main

import (
  "os"
  "path/filepath"
  "testing"
)

func TestValidName(t *testing.T) {
  good := []string{"dock.example.com", "user@example.com", "a-b_c.d"}
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
  orgName, rootCN, signCN = "Acme", "Acme Root CA", "Acme Sign CA"
  baseDir = "/data/my-ca"
  if err := saveConf(); err != nil {
    t.Fatal(err)
  }
  orgName, rootCN, signCN = "", "", ""
  baseDir = "/somewhere/else"
  if err := loadConf(); err != nil {
    t.Fatal(err)
  }
  if baseDir != "/data/my-ca" || orgName != "Acme" ||
    rootCN != "Acme Root CA" || signCN != "Acme Sign CA" {
    t.Fatalf("round trip mismatch: dir=%q org=%q root=%q sign=%q",
      baseDir, orgName, rootCN, signCN)
  }
  if !identityConfigured() {
    t.Fatal("identity should be configured after load")
  }
  p := home + "/ca-go/ca-go.conf"
  if _, err := os.Stat(p); err != nil {
    t.Fatalf("conf file missing: %v", err)
  }
}
