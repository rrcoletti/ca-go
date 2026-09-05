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
  "os"
  "path/filepath"
  "strings"
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
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Test Org", "Test Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })
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
  if len(m.fields) != 2 {
    t.Fatalf("expected 2 fields, got %d", len(m.fields))
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
  for i := 1; i < 2; i++ {
    if got := m.fields[i].input.Value(); got != "" {
      t.Fatalf("field %d leaked input: %q", i, got)
    }
  }
  // one tab per field: fill 0, move to 1
  m = keys(m, []tea.KeyMsg{{Type: tea.KeyTab}})
  m = keys(m, runes("two"))

  want := []string{"pass1", "two"}
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
  if _, err := os.Stat(rootCrlPath()); err != nil {
    t.Fatalf("CRL missing: %v", err)
  }
}

// Without a configured identity the TUI starts on the setup form; filling
// it saves the conf and sets the identity.
func TestFirstRunSetup(t *testing.T) {
  chdirCA(t)
  t.Setenv("XDG_CONFIG_HOME", t.TempDir())
  t.Setenv("HOME", t.TempDir())
  orgName, rootCN = "", ""

  m := initialModel()
  if m.screen != scrForm || m.action != actSetup || len(m.fields) != 3 {
    t.Fatalf("expected setup form with 3 fields, got screen=%d action=%d fields=%d",
      m.screen, m.action, len(m.fields))
  }
  tab := tea.KeyMsg{Type: tea.KeyTab}
  inputs := []string{"Example", "Example Root CA"}
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
  if orgName != "Example" || rootCN != "Example Root CA" {
    t.Fatalf("identity not set: %q %q", orgName, rootCN)
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
  if m.screen != scrForm || m.action != actSettings || len(m.fields) != 3 {
    t.Fatalf("expected settings form with 3 fields, got screen=%d action=%d fields=%d",
      m.screen, m.action, len(m.fields))
  }
  if got := m.fields[2].input.Value(); got != baseDir {
    t.Fatalf("dir field = %q, want current baseDir %q", got, baseDir)
  }
  tab := tea.KeyMsg{Type: tea.KeyTab}
  bs := tea.KeyMsg{Type: tea.KeyBackspace}
  newVals := []string{"New Org", "New Root CA"}
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
  if orgName != "New Org" || rootCN != "New Root CA" {
    t.Fatalf("identity not updated: %q %q", orgName, rootCN)
  }
  before := baseDir
  orgName, rootCN = "", ""
  if err := loadConf(); err != nil {
    t.Fatal(err)
  }
  if baseDir != before || orgName != "New Org" || rootCN != "New Root CA" {
    t.Fatalf("conf not persisted: dir=%q org=%q root=%q", baseDir, orgName, rootCN)
  }
}

// Submitting an identity that disagrees with an existing CA refuses to
// save: the form stays open with the alert, and the conf is untouched.
func TestEditConfRefusesOnMismatch(t *testing.T) {
  chdirCA(t)
  t.Setenv("XDG_CONFIG_HOME", t.TempDir())
  t.Setenv("HOME", t.TempDir())

  // stub CA cert on disk (unreadable as DER, which counts as mismatch)
  for _, p := range []func() string{rootCertPath} {
    if err := os.MkdirAll(filepath.Dir(p()), 0700); err != nil {
      t.Fatal(err)
    }
    if err := os.WriteFile(p(), []byte("stub"), 0600); err != nil {
      t.Fatal(err)
    }
  }

  m := initialModel()
  for i := 0; i < 7; i++ {
    next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
    m = next.(model)
  }
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  for i := 0; i < 2; i++ {
    m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
    m = m2.(model)
  }
  m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = m2.(model)

  // the refusal is shown on the result screen like every other warning
  if m.screen != scrResult {
    t.Fatalf("expected result screen, got screen=%d err=%s", m.screen, m.errMsg)
  }
  if !strings.Contains(m.errMsg, "configuration NOT saved") || !strings.Contains(m.errMsg, "rm -rf") {
    t.Fatalf("missing refusal alert: %q", m.errMsg)
  }
  if orgName != "Test Org" || rootCN != "Test Root CA" {
    t.Fatalf("globals were modified: %q %q", orgName, rootCN)
  }
  confPath, _ := confPath()
  if _, err := os.Stat(confPath); !os.IsNotExist(err) {
    t.Fatal("conf file was written despite refusal")
  }
}

// Opening Edit configuration after another form must not inherit that
// form's leftover fields.
func TestEditConfAfterServerFormIsClean(t *testing.T) {
  chdirCA(t)

  m := initialModel()
  m.menuIdx = 2 // New server certificate
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if len(m.fields) != 3 {
    t.Fatalf("expected 3 server-cert fields, got %d", len(m.fields))
  }
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc}) // back to menu, fields retained
  m = next.(model)
  if len(m.fields) != 3 {
    t.Fatalf("precondition: fields should still exist, got %d", len(m.fields))
  }

  m.menuIdx = 7 // Edit configuration
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrForm || m.action != actSettings {
    t.Fatalf("expected settings form, got screen=%d action=%d", m.screen, m.action)
  }
  if len(m.fields) != 3 {
    t.Fatalf("expected exactly 3 settings fields, got %d", len(m.fields))
  }
  want := []string{"Organization", "Root CA CN", "CA directory"}
  for i, w := range want {
    if m.fields[i].label != w {
      t.Fatalf("field %d label = %q, want %q", i, m.fields[i].label, w)
    }
  }
}

// Esc on the main menu quits; Esc everywhere else backs out one level.
func TestEscOnMenuQuits(t *testing.T) {
  chdirCA(t)
  m := initialModel()
  _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
  if cmd == nil {
    t.Fatal("esc on menu should return a quit cmd")
  }
  if msg := cmd(); msg != tea.Quit() {
    t.Fatalf("expected tea.Quit, got %v", msg)
  }
}

// Reproduction: issue a user certificate through the TUI, then open
// "Revoke user certificate" — the fresh cert must be on the list.
func TestRevokeListSeesTUIIssuance(t *testing.T) {
  chdirCA(t)
  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }

  m := initialModel()
  m.menuIdx = 4 // New user certificate
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrForm || m.action != actUser {
    t.Fatalf("expected user form, got screen=%d", m.screen)
  }

  inputs := []string{"User Name", "user@example.com", "up", "up", "rp", ""}
  for _, v := range inputs {
    m = keys(m, runes(v))
    m2, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // advance; submits on last
    m = m2.(model)
    if cmd != nil {
      msg := cmd()
      m2, _ = m.Update(msg) // doneMsg
      m = m2.(model)
    }
  }
  if m.screen != scrResult || m.errMsg != "" {
    t.Fatalf("issuance failed: screen=%d err=%s", m.screen, m.errMsg)
  }

  // back to menu, open Revoke user certificate (menu item 5)
  m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = m2.(model)
  m.menuIdx = 5
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)

  // one valid user cert: the pick list still shows, for confirmation
  if m.screen != scrPick {
    t.Fatalf("expected pick screen, got screen=%d err=%s", m.screen, m.errMsg)
  }
  if len(m.picks) != 1 || m.picks[0] != "user@example.com" {
    t.Fatalf("revoke list does not contain the fresh cert: %v", m.picks)
  }
  // Enter confirms the pick and asks for the CA passphrase
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrForm || len(m.fields) != 1 {
    t.Fatalf("expected passphrase form after confirming pick, got screen=%d fields=%d", m.screen, len(m.fields))
  }

  // Esc backs out to the pick list, not to the menu, and the header
  // names the kind being revoked
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
  m = next.(model)
  if m.screen != scrPick || len(m.picks) != 1 {
    t.Fatalf("expected pick screen after Esc, got screen=%d picks=%d", m.screen, len(m.picks))
  }
  if !strings.Contains(m.View(), "User certificates:") {
    t.Fatalf("pick header should name the kind, got: %s", m.View())
  }
}

// Leaving "Show issued certificates" must not leak its rows into a
// later result screen (reproduction: show list, Esc, New CA with a CA
// already on disk).
func TestResultScreenHasNoStaleList(t *testing.T) {
  chdirCA(t)
  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  if _, err := IssueServer("host.example.com", "rp", ""); err != nil {
    t.Fatal(err)
  }

  m := initialModel()
  m.menuIdx = 6 // Show issued certificates
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrList || len(m.lines) == 0 {
    t.Fatalf("expected list screen with rows, got screen=%d lines=%d", m.screen, len(m.lines))
  }

  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc}) // back to menu
  m = next.(model)
  m.menuIdx = 0 // New CA
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)

  if m.screen != scrResult {
    t.Fatalf("expected result screen, got %d", m.screen)
  }
  if len(m.lines) != 0 {
    t.Fatalf("stale list leaked into result screen: %v", m.lines)
  }
  if !strings.Contains(m.errMsg, "CA already exists") {
    t.Fatalf("expected CA-exists error, got %q", m.errMsg)
  }
}

// A "Show issued certificates" failure lands on the result screen,
// where the error is actually rendered (scrList ignores errMsg).
func TestShowErrorGoesToResultScreen(t *testing.T) {
  chdirCA(t)
  if err := os.MkdirAll(baseDir, 0700); err != nil {
    t.Fatal(err)
  }
  if err := os.WriteFile(filepath.Join(baseDir, "state.json"), []byte("not json"), 0600); err != nil {
    t.Fatal(err)
  }

  m := initialModel()
  m.menuIdx = 6 // Show issued certificates
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrResult {
    t.Fatalf("expected result screen, got %d", m.screen)
  }
  if !strings.Contains(m.errMsg, "corrupt") {
    t.Fatalf("expected corrupt-state error, got %q", m.errMsg)
  }
}
