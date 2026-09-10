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
  if len(m.fields) != 5 {
    t.Fatalf("expected 5 server-cert fields, got %d", len(m.fields))
  }
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc}) // back to menu, fields retained
  m = next.(model)
  if len(m.fields) != 5 {
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

// Show on a CA with zero issued certificates must render the notice,
// not a blank screen (a nil records slice used to fall through to the
// stale-lines branch of View).
func TestShowEmptyListRendersNotice(t *testing.T) {
  chdirCA(t)
  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  m := initialModel()
  m.menuIdx = 6 // Show issued certificates
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrList || m.recs == nil {
    t.Fatalf("expected list screen with normalized records, got screen=%d recs=%v", m.screen, m.recs)
  }
  if !strings.Contains(m.View(), "No certificates issued yet.") {
    t.Fatal("empty list view must render the notice:\n" + m.View())
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
  if _, err := IssueServer("host.example.com", "", "rp", ""); err != nil {
    t.Fatal(err)
  }

  m := initialModel()
  m.menuIdx = 6 // Show issued certificates
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrList || len(m.recs) == 0 {
    t.Fatalf("expected list screen with rows, got screen=%d recs=%d", m.screen, len(m.recs))
  }
  if !strings.Contains(m.View(), "host.example.com") {
    t.Fatal("list view must render the issued record")
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

// Changing the CA directory in Edit configuration must offer to move
// the existing CA; answering yes relocates the tree and saves the conf.
func TestSettingsDirChangeMovesCA(t *testing.T) {
  t.Setenv("XDG_CONFIG_HOME", t.TempDir())
  t.Setenv("HOME", t.TempDir())
  chdirCA(t)
  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  oldDir := baseDir
  newDir := filepath.Join(filepath.Dir(oldDir), "moved-ca")

  m := openSettingsForm(t)
  m.focus = 2 // submit on Enter only from the last field
  m.fields[2].input.SetValue(newDir)
  var next tea.Model
  var cmd tea.Cmd
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrConfirm {
    t.Fatalf("expected confirm screen, got %d (err: %s)", m.screen, m.errMsg)
  }

  next, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // "Yes, move it"
  m = next.(model)
  done := cmd().(doneMsg)
  next, _ = m.Update(done)
  m = next.(model)
  if m.screen != scrResult || m.errMsg != "" {
    t.Fatalf("expected clean result, got screen=%d err=%s", m.screen, m.errMsg)
  }
  if ok, err := exists(filepath.Join(newDir, "ca-root/certs/root-ca.crt")); err != nil || !ok {
    t.Fatal("root CA must exist in the new directory after the move")
  }
  if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
    t.Fatal("old directory must be gone after the move")
  }
  if baseDir != newDir {
    t.Fatalf("baseDir = %q, want %q", baseDir, newDir)
  }
  p, _ := confPath()
  data, _ := os.ReadFile(p)
  if !strings.Contains(string(data), newDir) {
    t.Fatal("conf file must contain the new directory")
  }
}

// Answering no keeps the CA in the old directory but still saves the
// new location.
func TestSettingsDirChangeNoKeepsCA(t *testing.T) {
  t.Setenv("XDG_CONFIG_HOME", t.TempDir())
  t.Setenv("HOME", t.TempDir())
  chdirCA(t)
  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  oldDir := baseDir
  newDir := filepath.Join(t.TempDir(), "elsewhere")

  m := openSettingsForm(t)
  m.focus = 2 // submit on Enter only from the last field
  m.fields[2].input.SetValue(newDir)
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrConfirm {
    t.Fatalf("expected confirm screen, got %d", m.screen)
  }
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown}) // "No, keep it where it is"
  m = next.(model)
  next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrResult || m.errMsg != "" {
    t.Fatalf("expected clean result, got screen=%d err=%s", m.screen, m.errMsg)
  }
  if ok, err := exists(filepath.Join(oldDir, "ca-root/certs/root-ca.crt")); err != nil || !ok {
    t.Fatal("CA must stay in the old directory after answering no")
  }
  if baseDir != newDir {
    t.Fatalf("baseDir = %q, want %q", baseDir, newDir)
  }
}

// With a CA in the old dir, an identity edit together with a dir change
// must be checked against the CA that lives there, not the empty target.
func TestSettingsDirChangeIdentityCheckedAgainstOldDir(t *testing.T) {
  t.Setenv("XDG_CONFIG_HOME", t.TempDir())
  t.Setenv("HOME", t.TempDir())
  chdirCA(t)
  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  newDir := filepath.Join(t.TempDir(), "moved")

  m := openSettingsForm(t)
  m.focus = 2 // submit on Enter only from the last field
  m.fields[0].input.SetValue("Wrong Org")
  m.fields[2].input.SetValue(newDir)
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrResult || m.errMsg == "" {
    t.Fatalf("expected mismatch refusal, got screen=%d err=%q", m.screen, m.errMsg)
  }
  if !strings.Contains(m.errMsg, "does not match") {
    t.Fatalf("expected mismatch message, got: %q", m.errMsg)
  }
}

// openSettingsForm opens Edit configuration with the fields prefilled.
func openSettingsForm(t *testing.T) model {
  t.Helper()
  m := initialModel()
  for i := 0; i < 7; i++ { // menu item 7 = Edit configuration
    next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
    m = next.(model)
  }
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
  m = next.(model)
  if m.screen != scrForm || m.action != actSettings {
    t.Fatalf("expected settings form, got screen=%d", m.screen)
  }
  return m
}

func keyMsg(s string) tea.KeyMsg {
  switch s {
  case "enter":
    return tea.KeyMsg{Type: tea.KeyEnter}
  case "esc":
    return tea.KeyMsg{Type: tea.KeyEscape}
  case "y":
    return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")}
  case "n":
    return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")}
  }
  return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// The startup sanity screen: it appears when artifacts are missing,
// the first finding is preselected so Enter works immediately, a p12
// repair goes through the passphrase form, a chain repair runs
// directly, and Esc continues to the menu.
func TestSanityScreenFlow(t *testing.T) {
  oldBase := baseDir
  baseDir = t.TempDir()
  t.Cleanup(func() { baseDir = oldBase })
  oldOrg, oldRoot := orgName, rootCN
  orgName, rootCN = "Example", "Example Root CA"
  t.Cleanup(func() { orgName, rootCN = oldOrg, oldRoot })

  if _, err := NewCA("rp"); err != nil {
    t.Fatal(err)
  }
  if _, err := IssueServer("h.example.com", "", "rp", ""); err != nil {
    t.Fatal(err)
  }
  p12 := filepath.Join(baseDir, "servers/p12/h.example.com.p12")
  chain := filepath.Join(baseDir, "servers/certs/h.example.com-chain.pem")
  os.Remove(p12)
  os.Remove(chain)

  m0 := initialModel()
  if m0.screen != scrSanity || len(m0.sanity) != 2 {
    t.Fatalf("expected sanity screen with 2 findings, got screen=%d n=%d", m0.screen, len(m0.sanity))
  }
  if m0.sanIdx != 0 {
    t.Fatalf("sanIdx = %d, want 0: Enter must work without a prior keypress", m0.sanIdx)
  }

  // every content row starts at the same column, selected or not
  v := m0.View()
  if strings.Count(v, "do you want to regenerate it?  [y/N]") != 2 {
    t.Errorf("p12 and chain rows must both ask the y/N question, got: %q", v)
  }
  for _, l := range strings.Split(v, "\n") {
    if !strings.Contains(l, "missing") {
      continue
    }
    plain := strings.ReplaceAll(l, "\x1b", "")
    if strings.HasPrefix(strings.TrimLeft(plain, " "), ">") {
      if !strings.HasPrefix(plain, "      > ") {
        t.Errorf("selected row not at the common column: %q", plain)
      }
    } else if !strings.HasPrefix(plain, "        ") {
      t.Errorf("unselected row not at the common column: %q", plain)
    }
  }

  // y on the preselected p12 finding opens the passphrase form
  m1, cmd := m0.updateSanity(keyMsg("y"))
  mm := m1.(model)
  if mm.screen != scrForm || mm.action != actSanityP12 || len(mm.fields) != 2 || cmd == nil {
    t.Fatalf("enter should open the p12 passphrase form, got screen=%d action=%d fields=%d",
      mm.screen, mm.action, len(mm.fields))
  }

  // submitting the form regenerates the bundle (full TUI path)
  mm.fields[0].input.SetValue("rp")
  m2, cmd2 := mm.submitForm()
  if cmd2 == nil {
    t.Fatal("expected a repair command")
  }
  dm, ok := cmd2().(doneMsg)
  if !ok || dm.err != nil {
    t.Fatalf("p12 repair failed: %+v", dm)
  }
  if _, err := os.Stat(p12); err != nil {
    t.Fatal("p12 file not rebuilt")
  }
  m3, _ := m2.Update(dm)
  if m3.(model).screen != scrResult {
    t.Fatalf("expected result screen after repair, got %d", m3.(model).screen)
  }

  // the chain finding (now the only one) is preselected; Enter
  // repairs it directly
  m4 := initialModel()
  if m4.screen != scrSanity || len(m4.sanity) != 1 {
    t.Fatalf("expected 1 remaining finding, got screen=%d n=%d", m4.screen, len(m4.sanity))
  }
  m5, cmd3 := m4.updateSanity(keyMsg("y"))
  if cmd3 == nil {
    t.Fatal("expected a repair command for the chain finding")
  }
  dm2, ok := cmd3().(doneMsg)
  if !ok || dm2.err != nil {
    t.Fatalf("chain repair failed: %+v", dm2)
  }
  if _, err := os.Stat(chain); err != nil {
    t.Fatal("chain file not rebuilt")
  }
  _ = m5

  // Esc continues to the menu even with findings left
  m6, _ := m4.updateSanity(keyMsg("esc"))
  if m6.(model).screen != scrMenu {
    t.Fatalf("expected menu after Esc, got %d", m6.(model).screen)
  }

  // Enter defaults to N on a p12 question: the selection moves on,
  // the form does not open
  os.Remove(filepath.Join(baseDir, "servers/p12/h.example.com.p12"))
  mp := initialModel()
  if mp.screen != scrSanity || mp.sanity[0].Kind != "p12" {
    t.Fatalf("expected the p12 finding preselected, got screen=%d", mp.screen)
  }
  mp2, _ := mp.updateSanity(keyMsg("enter"))
  if mp2.(model).screen != scrMenu {
    t.Fatalf("enter on the only p12 finding must continue to the menu, got screen=%d", mp2.(model).screen)
  }
  // with two findings, N skips to the second instead of opening the form
  mp4 := mp
  mp4.sanity = []SanityIssue{mp.sanity[0], {Kind: "p12", Name: "other", KindDir: "servers"}}
  mp4b, _ := mp4.updateSanity(keyMsg("n"))
  if mp4b.(model).screen != scrSanity || mp4b.(model).sanIdx != 1 {
    t.Fatalf("N must skip to the next finding, got screen=%d idx=%d", mp4b.(model).screen, mp4b.(model).sanIdx)
  }
  mp4c, _ := mp4b.(model).updateSanity(keyMsg("n"))
  if mp4c.(model).screen != scrMenu {
    t.Fatalf("N on the last finding must continue to the menu, got screen=%d", mp4c.(model).screen)
  }
  _ = mp2
  mp3, _ := mp.updateSanity(keyMsg("y"))
  if mp3.(model).screen != scrForm || mp3.(model).action != actSanityP12 {
    t.Fatalf("y must open the p12 form, got screen=%d", mp3.(model).screen)
  }
  // close the check cleanly: rebuild the bundle so later sections
  // see only their own findings
  if _, err := RegenerateP12("server", "h.example.com", "", ""); err != nil {
    t.Fatal(err)
  }

  // a user key is always encrypted: an empty key passphrase is
  // rejected with an error, not submitted
  if _, err := IssueUser("U One", "u1@example.com", "up", "rp", ""); err != nil {
    t.Fatal(err)
  }
  os.Remove(filepath.Join(baseDir, "users/p12/u1@example.com.p12"))
  mu := initialModel()
  if mu.screen != scrSanity || len(mu.sanity) != 1 || mu.sanity[0].KindDir != "users" {
    t.Fatalf("expected the user p12 finding, got screen=%d n=%d", mu.screen, len(mu.sanity))
  }
  mu2, _ := mu.updateSanity(keyMsg("y"))
  mmu := mu2.(model)
  if !strings.Contains(mmu.fields[0].label, "key passphrase") || strings.Contains(mmu.fields[0].label, "unencrypted") {
    t.Fatalf("user key label must not suggest an unencrypted key: %q", mmu.fields[0].label)
  }
  mmu2, _ := mmu.submitForm()
  if mmu2.screen != scrForm || !strings.Contains(mmu2.errMsg, "user key passphrase must not be empty") {
    t.Fatalf("empty user key passphrase must be rejected, got screen=%d err=%q",
      mmu2.screen, mmu2.errMsg)
  }
}
