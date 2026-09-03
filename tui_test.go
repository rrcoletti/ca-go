package main

import (
  "os"
  "testing"

  tea "github.com/charmbracelet/bubbletea"
)

// chdirCA isolates each test in its own empty directory.
func chdirCA(t *testing.T) {
  t.Helper()
  old, err := os.Getwd()
  if err != nil {
    t.Fatal(err)
  }
  t.Cleanup(func() { os.Chdir(old) })
  os.Chdir(t.TempDir())
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
  old, _ := os.Getwd()
  os.Chdir(dir)
  defer os.Chdir(old)

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
  if _, err := os.Stat(rootCertPath); err != nil {
    t.Fatalf("root cert missing: %v", err)
  }
  if _, err := os.Stat(signChainPath); err != nil {
    t.Fatalf("chain missing: %v", err)
  }
}
