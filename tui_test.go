package main

import (
  "os"
  "testing"

  tea "github.com/charmbracelet/bubbletea"
)

// chdirCA isolates each test in its own empty directory and pre-configures
// the identity so initialModel goes straight to the menu.
func chdirCA(t *testing.T) {
  t.Helper()
  old := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = old })
  oldOrg, oldRoot, oldSign := orgName, rootCN, signCN
  orgName, rootCN, signCN = "Test Org", "Test Root CA", "Test Sign CA"
  t.Cleanup(func() { orgName, rootCN, signCN = oldOrg, oldRoot, oldSign })
}

// keys feeds a sequence of keystrokes to the model.
func keys(m model, seq []tea.KeyMsg) model {
  for _, k := range seq {
    next, _ := m.Update(k)
    m = next.(model)
  }
  return m
}

func runes(s string) []tea.KeyMsg {
  out := []tea.KeyMsg{}
  for _, r := range s {
    out = append(out, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
  }
  return out
}

func openNewCAForm(t *testing.T) model {
  t.Helper()
  chdirCA(t)
  m := initialModel()
  m = keys(m, []tea.KeyMsg{{Type: tea.KeyEnter}}) // select New CA
  if m.screen != scrForm {
    t.Fatalf("expected form screen, got %d", m.screen)
  }
  if len(m.fields) != 4 {
    t.Fatalf("expected 4 fields, got %d", len(m.fields))
  }
  return m
}

// Typing into the focused field must not leak into the other fields.
func TestNewCAFieldsAreIndependent(t *testing.T) {
  m := openNewCAForm(t)
  m = keys(m, runes("pass1"))
  if got := m.fields[0].input.Value(); got != "pass1" {
    t.Fatalf("field 0 = %q", got)
  }
  for i := 1; i < 4; i++ {
    if got := m.fields[i].input.Value(); got != "" {
      t.Fatalf("field %d leaked input: %q", i, got)
    }
  }
  // one tab per field: fill 0, move to 1, 2, 3
  m = keys(m, []tea.KeyMsg{{Type: tea.KeyTab}})
  m = keys(m, runes("two"))
  m = keys(m, []tea.KeyMsg{{Type: tea.KeyTab}})
  m = keys(m, runes("three"))
  m = keys(m, []tea.KeyMsg{{Type: tea.KeyTab}})
  m = keys(m, runes("four"))

  want := []string{"pass1", "two", "three", "four"}
  for i, w := range want {
    if got := m.fields[i].input.Value(); got != w {
      t.Fatalf("field %d = %q, want %q", i, got, w)
    }
  }
}

// Mismatched confirmation keeps the form open with an error message.
func TestNewCAPassphraseMismatch(t *testing.T) {
  m := openNewCAForm(t)
  tab := tea.KeyMsg{Type: tea.KeyTab}
  m = keys(m, runes("aaa"))
  m = keys(m, []tea.KeyMsg{tab})
  m = keys(m, runes("bbb"))
  m = keys(m, []tea.KeyMsg{tab})
  m = keys(m, runes("ccc"))
  m = keys(m, []tea.KeyMsg{tab})
  m = keys(m, runes("ddd"))
  m = keys(m, []tea.KeyMsg{{Type: tea.KeyEnter}})
  if m.errMsg == "" {
    t.Fatal("expected mismatch error message")
  }
  if m.screen != scrForm {
    t.Fatalf("expected to stay on form, got %d", m.screen)
  }
}

// Matching passphrases submit and create the CA.
func TestNewCAHappyPath(t *testing.T) {
  dir := t.TempDir()
  old := baseDir
  baseDir = dir
  defer func() { baseDir = old }()

  m := openNewCAForm(t)
  tab := tea.KeyMsg{Type: tea.KeyTab}
  m = keys(m, runes("rootpass"))
  m = keys(m, []tea.KeyMsg{tab})
  m = keys(m, runes("rootpass"))
  m = keys(m, []tea.KeyMsg{tab})
  m = keys(m, runes("signpass"))
  m = keys(m, []tea.KeyMsg{tab})
  m = keys(m, runes("signpass"))
  m2, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = m2.(model)
  if cmd == nil {
    t.Fatal("expected submit cmd")
  }
  msg := cmd()
  dm, ok := msg.(doneMsg)
  if !ok {
    t.Fatalf("expected doneMsg, got %T", msg)
  }
  if dm.err != nil {
    t.Fatalf("NewCA failed: %v", dm.err)
  }
  if _, err := os.Stat(rootCertPath()); err != nil {
    t.Fatalf("root cert missing: %v", err)
  }
  if _, err := os.Stat(signChainPath()); err != nil {
    t.Fatalf("chain missing: %v", err)
  }
}

// Without a configured identity the TUI starts on the setup form; filling
// it saves the conf and sets the identity.
func TestFirstRunSetup(t *testing.T) {
  chdirCA(t)
  t.Setenv("XDG_CONFIG_HOME", t.TempDir())
  t.Setenv("HOME", t.TempDir())
  orgName, rootCN, signCN = "", "", ""

  m := initialModel()
  if m.screen != scrForm || m.action != actSetup || len(m.fields) != 4 {
    t.Fatalf("expected setup form with 4 fields, got screen=%d action=%d fields=%d",
      m.screen, m.action, len(m.fields))
  }
  tab := tea.KeyMsg{Type: tea.KeyTab}
  inputs := []string{"Acme", "Acme Root CA", "Acme Sign CA"}
  for _, v := range inputs {
    m = keys(m, runes(v))
    m = keys(m, []tea.KeyMsg{tab})
  }
  m = keys(m, runes(baseDir))
  m2, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = m2.(model)
  if cmd != nil {
    t.Fatal("setup submit should not return a cmd")
  }
  if m.screen != scrResult {
    t.Fatalf("expected result screen, got %d (err: %s)", m.screen, m.errMsg)
  }
  if orgName != "Acme" || rootCN != "Acme Root CA" || signCN != "Acme Sign CA" {
    t.Fatalf("identity not set: %q %q %q", orgName, rootCN, signCN)
  }
  if !identityConfigured() {
    t.Fatal("identityConfigured() = false after setup")
  }
}

// "Edit configuration" opens a prefilled 4-field form; submitting saves
// the new values.
func TestEditConfForm(t *testing.T) {
  chdirCA(t)
  t.Setenv("XDG_CONFIG_HOME", t.TempDir())
  t.Setenv("HOME", t.TempDir())

  m := initialModel()
  for i := 0; i < 7; i++ { // menu item 7 = Edit configuration
    next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
    m = next.(model)
  }
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrForm || m.action != actSettings || len(m.fields) != 4 {
    t.Fatalf("expected settings form with 4 fields, got screen=%d action=%d fields=%d",
      m.screen, m.action, len(m.fields))
  }
  if got := m.fields[3].input.Value(); got != baseDir {
    t.Fatalf("dir field = %q, want current baseDir %q", got, baseDir)
  }
  tab := tea.KeyMsg{Type: tea.KeyTab}
  bs := tea.KeyMsg{Type: tea.KeyBackspace}
  newVals := []string{"New Org", "New Root CA", "New Sign CA"}
  for i, v := range newVals {
    n0 := len(m.fields[i].input.Value())
    for n := 0; n < n0; n++ { // clear prefilled text
      m = keys(m, []tea.KeyMsg{bs})
    }
    m = keys(m, runes(v))
    m = keys(m, []tea.KeyMsg{tab})
  }
  m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = m2.(model)
  if m.screen != scrResult {
    t.Fatalf("expected result screen, got %d (err: %s)", m.screen, m.errMsg)
  }
  if orgName != "New Org" || rootCN != "New Root CA" || signCN != "New Sign CA" {
    t.Fatalf("identity not updated: %q %q %q", orgName, rootCN, signCN)
  }
  before := baseDir
  orgName, rootCN, signCN = "", "", ""
  if err := loadConf(); err != nil {
    t.Fatal(err)
  }
  if baseDir != before || orgName != "New Org" || rootCN != "New Root CA" || signCN != "New Sign CA" {
    t.Fatalf("conf not persisted: dir=%q org=%q root=%q sign=%q", baseDir, orgName, rootCN, signCN)
  }
}
