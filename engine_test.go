package main

import (
  "os"
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
  old, err := os.Getwd()
  if err != nil {
    t.Fatal(err)
  }
  t.Cleanup(func() { os.Chdir(old) })
  os.Chdir(dir)

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
