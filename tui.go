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

// TUI built on Bubble Tea. Arrow keys/vi keys to navigate, Enter to select,
// Esc cancels a form or backs out of a screen; q or Esc on the menu quits.

import (
  "errors"
  "path/filepath"
  "strings"

  "github.com/charmbracelet/bubbles/textinput"
  tea "github.com/charmbracelet/bubbletea"
  "github.com/charmbracelet/lipgloss"
  "github.com/charmbracelet/x/ansi"
)

type screen int

const (
  scrMenu screen = iota
  scrForm
  scrPick
  scrRunning
  scrList
  scrConfirm
  scrSanity
)

type action int

const (
  actNewCA action = iota
  actCRL
  actServer
  actRevokeServer
  actUser
  actRevokeUser
  actShow
  actSettings
  actSetup
  actSanityP12
)

var menuItems = []string{
  "New CA",
  "Regenerate CRL",
  "New server certificate",
  "Revoke server certificate",
  "New user certificate",
  "Revoke user certificate",
  "Show issued certificates",
  "Edit configuration",
  "Quit",
}

var (
  titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
  boxStyle      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238"))
  selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
  normalStyle   = lipgloss.NewStyle()
  errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
  okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
  warnStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
  helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

type field struct {
  label string
  input textinput.Model
}

type doneMsg struct {
  lines []string
  err   error
}

type model struct {
  screen  screen
  action  action
  menuIdx int
  fields  []field
  focus   int
  picks   []string
  pickIdx int
  lines   []string
  recs    []CertRecord // show screen: rendered per frame at m.width
  moveFrom, moveTo string // pending CA move (settings dir change)
  sanity  []SanityIssue // startup sanity check findings
  sanIdx  int           // selected finding on the sanity screen
  errMsg  string
  width   int // terminal size, 0 until the first WindowSizeMsg
  height  int
  modal     bool   // result overlay open over the current screen
  modalErr  bool   // the overlay shows an error
  returnScr screen // screen an error overlay reopens on Enter
}

// showModal opens the result overlay. Success overlays sit over the
// menu; error overlays reopen back (the screen the action was launched
// from) so the filled-in form stays on screen for corrections.
func (m *model) showModal(lines []string, err error, back screen) {
  m.modal = true
  m.modalErr = err != nil
  m.returnScr = back
  m.lines = lines
  m.errMsg = ""
  if err != nil {
    m.errMsg = err.Error()
  }
}

func initialModel() model {
  m := model{screen: scrMenu}
  if !identityConfigured() {
    // first run: setup form (org, root CN, directory)
    m.screen = scrForm
    m.action = actSetup
    m.focus = 0
    defs := []struct{ label, val string }{
      {"Organization", ""},
      {"Root CA CN", ""},
      {"CA directory", baseDir},
    }
    for _, d := range defs {
      f := newField(d.label, "", false)
      f.input.SetValue(d.val)
      m.fields = append(m.fields, f)
    }
    m.fields[0].input.Focus()
    return m
  }
  // startup sanity check: surface missing artifacts before anything else
  if iss, err := SanityIssues(); err == nil && len(iss) > 0 {
    m.screen = scrSanity
    m.sanity = iss
  }
  return m
}

func newField(label, placeholder string, masked bool) field {
  ti := textinput.New()
  ti.Placeholder = placeholder
  ti.CharLimit = 128
  ti.Width = 40
  if masked {
    ti.EchoMode = textinput.EchoPassword
  }
  return field{label: label, input: ti}
}

// form definitions per action
func (m model) startForm(act action) (tea.Model, tea.Cmd) {
  m.screen = scrForm
  m.action = act
  m.focus = 0
  m.fields = nil
  m.errMsg = ""
  add := func(label, placeholder string, masked bool) {
    f := newField(label, placeholder, masked)
    m.fields = append(m.fields, f)
  }
  switch act {
  case actNewCA:
    add("Root CA passphrase", "", true)
    add("Confirm root passphrase", "", true)
  case actCRL:
    add("CA passphrase", "", true)
  case actServer:
    add("FQDN (e.g. host.example.com)", "", false)
    add("Server key passphrase (empty = none)", "", true)
    add("Confirm server key passphrase", "", true)
    add("CA passphrase", "", true)
    add("p12 export passphrase (empty = none)", "", true)
  case actUser:
    add("Common name (e.g. User Name)", "", false)
    add("Email (e.g. name@example.com)", "", false)
    add("User passphrase", "", true)
    add("Confirm user passphrase", "", true)
    add("CA passphrase", "", true)
    add("p12 export passphrase (empty = none)", "", true)
  case actRevokeServer, actRevokeUser:
    kind := "server"
    if act == actRevokeUser {
      kind = "user"
    }
    recs, err := ListIssued()
    if err != nil {
      m.showModal(nil, err, scrMenu)
      return m, nil
    }
    m.picks = nil
    for _, r := range recs {
      if r.Kind == kind && !r.Revoked {
        m.picks = append(m.picks, r.Name)
      }
    }
    if len(m.picks) == 0 {
      m.showModal([]string{"No " + kind + " certificates to revoke."}, nil, scrMenu)
      return m, nil
    }
    // always show the pick list, even for a single candidate: revoke is
    // destructive and the user must see what they are about to revoke
    m.pickIdx = 0
    m.screen = scrPick
    return m, nil
  }
  m.fields[0].input.Focus()
  return m, textinput.Blink
}

// formValues returns the field values. Visible inputs are trimmed;
// password inputs are taken verbatim so spaces in passphrases survive.
func (m model) formValues() []string {
  vals := make([]string, len(m.fields))
  for i, f := range m.fields {
    v := f.input.Value()
    if f.input.EchoMode != textinput.EchoPassword {
      v = strings.TrimSpace(v)
    }
    vals[i] = v
  }
  return vals
}

func (m model) submitForm() (model, tea.Cmd) {
  vals := m.formValues()
  act := m.action

  // validations
  if act == actNewCA {
    if vals[0] == "" {
      m.errMsg = "passphrase must not be empty"
      return m, nil
    }
    if vals[0] != vals[1] {
      m.errMsg = "passphrases do not match"
      return m, nil
    }
  }
  if act == actUser {
    if vals[0] == "" {
      m.errMsg = "common name must not be empty"
      return m, nil
    }
    if !validEmail(vals[1]) {
      m.errMsg = "email must be in the format name@example.com"
      return m, nil
    }
    if vals[2] == "" || vals[2] != vals[3] {
      m.errMsg = "user passphrases empty or do not match"
      return m, nil
    }
  }
  if act == actCRL && vals[0] == "" {
    m.errMsg = "passphrase must not be empty"
    return m, nil
  }
  if act == actSanityP12 && m.sanity[m.sanIdx].KindDir == "users" && vals[0] == "" {
    m.errMsg = "user key passphrase must not be empty"
    return m, nil
  }
  if act == actServer {
    if vals[0] == "" {
      m.errMsg = "fqdn must not be empty"
      return m, nil
    }
    if vals[1] != vals[2] {
      m.errMsg = "server key passphrases do not match"
      return m, nil
    }
  }
  if act == actSettings || act == actSetup {
    for i, label := range []string{"organization", "root CA CN"} {
      if vals[i] == "" {
        m.errMsg = label + " must not be empty"
        return m, nil
      }
    }
    if !validDir(vals[2]) {
      m.errMsg = "directory must be an absolute path using only letters, digits, '/', '.', '-' and '_'"
      return m, nil
    }
    // Edit configuration only: the identity must match the CA wherever
    // it currently lives; saving a different identity would desync
    // config and certificates: refuse and alert
    if act == actSettings {
      oldDir := baseDir
      moving := vals[2] != oldDir
      oldRootExists, err := exists(filepath.Join(oldDir, "ca-root/certs/root-ca.crt"))
      if err != nil {
        m.errMsg = err.Error()
        return m, nil
      }
      // when the CA will be moved, its identity lives in the old dir
      checkDir := vals[2]
      if moving && oldRootExists {
        checkDir = oldDir
      }
      rootExists, err := exists(filepath.Join(checkDir, "ca-root/certs/root-ca.crt"))
      if err != nil {
        m.errMsg = err.Error()
        return m, nil
      }
      if rootExists {
        _, bad := caIdentityMismatches(checkDir, vals[0], vals[1])
        if len(bad) > 0 {
          msg := strings.Join([]string{
            "configuration NOT saved.",
            "",
            "The CA certificate does not match the new configuration:",
          }, "\n")
          for _, b := range bad {
            msg += "\n    - " + b
          }
          msg += strings.Join([]string{
            "",
            "",
            "Check the values and try again, or, if you want a clean CA, remove the existing one manually:",
            "",
            "  $ " + removeCommandFor(checkDir),
          }, "\n")
          // shown as an overlay like every other warning; Enter
          // reopens the form with the values still in place
          m.showModal(nil, errors.New(msg), scrForm)
          return m, nil
        }
      }
      // the CA exists in the old dir and the dir is changing: offer to
      // move the whole tree to the new location
      if oldRootExists {
        m.moveFrom, m.moveTo = oldDir, vals[2]
        m.pickIdx = 0
        m.screen = scrConfirm
        return m, nil
      }
    }
    orgName, rootCN = vals[0], vals[1]
    baseDir = vals[2]
    if err := saveConf(); err != nil {
      m.errMsg = err.Error()
      return m, nil
    }
    m.showModal([]string{"Configuration saved."}, nil, scrMenu)
    return m, nil
  }

  m.returnScr = scrForm
  m.screen = scrRunning
  m.errMsg = ""
  return m, func() tea.Msg {
    var lines []string
    var err error
    switch act {
    case actNewCA:
      lines, err = NewCA(vals[0])
    case actCRL:
      lines, err = RegenerateCRL(vals[0])
    case actServer:
      lines, err = IssueServer(vals[0], vals[1], vals[3], vals[4])
    case actUser:
      lines, err = IssueUser(vals[0], vals[1], vals[2], vals[4], vals[5])
    case actSanityP12:
      s := m.sanity[m.sanIdx]
      kind := "server"
      if s.KindDir == "users" {
        kind = "user"
      }
      lines, err = RegenerateP12(kind, s.Name, vals[0], vals[1])
    }
    return doneMsg{lines: lines, err: err}
  }
}

// submitRevokePass validates the passphrase form and runs the revocation.
func (m model) submitRevokePass() (model, tea.Cmd) {
  vals := m.formValues()
  if vals[0] == "" {
    m.errMsg = "passphrase must not be empty"
    return m, nil
  }
  name := m.picks[0]
  if len(m.picks) > 1 {
    name = m.picks[m.pickIdx]
  }
  kind := "server"
  if m.action == actRevokeUser {
    kind = "user"
  }
  m.returnScr = scrForm
  m.screen = scrRunning
  return m, func() tea.Msg {
    lines, err := Revoke(kind, name, vals[0])
    return doneMsg{lines: lines, err: err}
  }
}

// wrapText word-wraps s at width, preserving existing newlines.
// Narrow or unknown widths fall back to 80 columns.
func wrapText(s string, width int) string {
  if width < 20 {
    width = 80
  }
  var out []string
  for _, line := range strings.Split(s, "\n") {
    // rune-aware: the ellipsis in truncated rows is 3 bytes, and byte
    // counting would wrap a line that still fits the terminal
    r := []rune(line)
    for len(r) > width {
      // last space within the width, else hard cut
      cut := width
      for i := width; i > 0; i-- {
        if r[i-1] == ' ' {
          cut = i
          break
        }
      }
      out = append(out, strings.TrimRight(string(r[:cut]), " "))
      r = []rune(strings.TrimLeft(string(r[cut:]), " "))
    }
    out = append(out, string(r))
  }
  return strings.Join(out, "\n")
}

func (m model) Init() tea.Cmd {
  if m.screen == scrForm {
    return textinput.Blink
  }
  return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
  switch msg := msg.(type) {
  case tea.WindowSizeMsg:
    m.width = msg.Width
    m.height = msg.Height
    return m, nil
  case tea.KeyMsg:
    switch msg.String() {
    case "ctrl+c":
      return m, tea.Quit
    }
    if m.modal {
      // the overlay swallows everything except its close keys: Enter
      // reopens the screen it belongs to (the form on errors, the
      // menu on success), Esc and q behave the same
      switch msg.String() {
      case "enter", "esc", "q":
        m.modal = false
        m.lines = nil
        m.errMsg = ""
        if m.modalErr {
          m.screen = m.returnScr
          if len(m.fields) > 0 {
            return m, m.fields[m.focus].input.Focus()
          }
          return m, nil
        }
        m.screen = scrMenu
        m.sanity = nil
        return m, nil
      }
      return m, nil
    }
    switch m.screen {
    case scrMenu:
      return m.updateMenu(msg)
    case scrForm:
      return m.updateForm(msg)
    case scrPick:
      return m.updatePick(msg)
    case scrList:
      switch msg.String() {
      case "enter", "esc", "q":
        m.screen = scrMenu
        m.lines = nil
        m.recs = nil
        return m, nil
      }
    case scrConfirm:
      return m.updateConfirm(msg)
    case scrSanity:
      return m.updateSanity(msg)
    }
  case doneMsg:
    // the screen behind the overlay stays until Enter: nothing
    // changes before the user dismisses the result
    if msg.err != nil {
      m.showModal(msg.lines, msg.err, m.returnScr)
    } else {
      m.showModal(msg.lines, nil, scrMenu)
    }
    return m, nil
  }
  return m, nil
}

// updateSanity drives the startup sanity screen: y repairs the
// selected finding (a p12 asks for its passphrases first, a PEM chain
// rebuilds directly), N or Enter skips, on the last finding the menu
// follows; Esc or q continues there too. Manual findings are display
// only.
func (m model) updateSanity(msg tea.Msg) (tea.Model, tea.Cmd) {
  key, ok := msg.(tea.KeyMsg)
  if !ok {
    return m, nil
  }
  switch key.String() {
  case "up", "k":
    m.sanIdx = (m.sanIdx - 1 + len(m.sanity)) % len(m.sanity)
  case "down", "j":
    m.sanIdx = (m.sanIdx + 1) % len(m.sanity)
  case "y":
    if m.sanIdx >= len(m.sanity) {
      return m, nil
    }
    s := m.sanity[m.sanIdx]
    if s.Kind == "p12" {
      m.screen = scrForm
      m.action = actSanityP12
      m.focus = 0
      m.errMsg = ""
      m.fields = nil
      // user keys are always encrypted; only server keys may be
      // written unencrypted
      keyLabel := "key passphrase for " + s.Name + " (empty = unencrypted key)"
      if s.KindDir == "users" {
        keyLabel = "key passphrase for " + s.Name
      }
      for _, label := range []string{
        keyLabel,
        "p12 export passphrase (empty = none)",
      } {
        m.fields = append(m.fields, newField(label, "", true))
      }
      m.fields[0].input.Focus()
      return m, textinput.Blink
    }
    if s.Kind == "chain" {
      m.returnScr = scrSanity
      m.screen = scrRunning
      m.errMsg = ""
      return m, func() tea.Msg {
        kind := "server"
        if s.KindDir == "users" {
          kind = "user"
        }
        lines, err := RegenerateChain(kind, s.Name)
        return doneMsg{lines: lines, err: err}
      }
    }
  case "n", "enter":
    // answering no to a question: move on to the next finding;
    // on the last one, the check is done and the menu follows
    if m.sanIdx == len(m.sanity)-1 {
      m.screen = scrMenu
      m.sanity = nil
      return m, nil
    }
    m.sanIdx++
  case "esc", "q":
    m.screen = scrMenu
    m.sanity = nil
    return m, nil
  }
  return m, nil
}

func (m model) updateMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
  key, ok := msg.(tea.KeyMsg)
  if !ok {
    return m, nil
  }
  switch key.String() {
  case "up", "k":
    m.menuIdx = (m.menuIdx - 1 + len(menuItems)) % len(menuItems)
  case "down", "j":
    m.menuIdx = (m.menuIdx + 1) % len(menuItems)
  case "enter":
    if m.menuIdx == len(menuItems)-1 { // Quit
      return m, tea.Quit
    }
    var act action
    switch m.menuIdx {
    case 0:
      act = actNewCA
    case 1:
      act = actCRL
    case 2:
      act = actServer
    case 3:
      act = actRevokeServer
    case 4:
      act = actUser
    case 5:
      act = actRevokeUser
    case 6:
      act = actShow
    case 7:
      act = actSettings
    default:
      return m, nil
    }
    if act == actShow {
      recs, err := ListIssued()
      if err != nil {
        m.showModal(nil, err, scrMenu)
        return m, nil
      }
      m.lines = nil
      // normalize: a CA with no issued certs yields a nil slice, and
      // View() distinguishes "show screen" from "stale lines" by recs
      // being non-nil
      if recs == nil {
        recs = []CertRecord{}
      }
      m.recs = recs
      m.screen = scrList
      return m, nil
    }
    if act == actSettings {
      // prefilled form for the full configuration
      m.screen = scrForm
      m.action = actSettings
      m.focus = 0
      m.errMsg = ""
      m.fields = nil // discard any fields left over from a previous form
      defs := []struct{ label, val string }{
        {"Organization", orgName},
        {"Root CA CN", rootCN},
        {"CA directory", baseDir},
      }
      for _, d := range defs {
        f := newField(d.label, "", false)
        f.input.SetValue(d.val)
        m.fields = append(m.fields, f)
      }
      m.fields[0].input.Focus()
      return m, textinput.Blink
    }
    if act == actNewCA {
      rootExists, err := exists(rootCertPath())
      if err != nil {
        m.showModal(nil, err, scrMenu)
        return m, nil
      }
      if rootExists {
        m.showModal(nil, errors.New(caExistsMessage(baseDir)), scrMenu)
        return m, nil
      }
    }
    return m.startForm(act)
  case "q", "esc":
    return m, tea.Quit
  }
  return m, nil
}

// moveFocus moves form field focus by delta, wrapping around, and
// clears any stale error message.
func (m *model) moveFocus(delta int) tea.Cmd {
  m.focus = (m.focus + delta + len(m.fields)) % len(m.fields)
  cmds := []tea.Cmd{}
  for i := range m.fields {
    if i == m.focus {
      cmds = append(cmds, m.fields[i].input.Focus())
    } else {
      m.fields[i].input.Blur()
    }
  }
  m.errMsg = ""
  return tea.Batch(cmds...)
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
  if key, ok := msg.(tea.KeyMsg); ok {
    // up/down move focus, matched on the key TYPE: bubbletea coalesces
    // fast-typed runes (and tmux send-keys), so the literal word "up"
    // or "down" typed into a field arrives as one KeyRunes message
    // whose String() is also "up"/"down"; only true arrow keys have
    // KeyType KeyUp/KeyDown, so typed words can never navigate here
    if key.Type == tea.KeyUp || key.Type == tea.KeyDown {
      if key.Type == tea.KeyDown {
        return m, m.moveFocus(1)
      }
      return m, m.moveFocus(-1)
    }
    switch key.String() {
    case "esc":
      m.errMsg = ""
      if m.action == actRevokeServer || m.action == actRevokeUser {
        // back to the pick list, not out of the flow
        m.screen = scrPick
        return m, nil
      }
      m.screen = scrMenu
      return m, nil
    case "tab", "shift+tab":
      if key.String() == "tab" {
        return m, m.moveFocus(1)
      }
      return m, m.moveFocus(-1)
    case "enter":
      // advance to next field; submit on last
      if m.focus < len(m.fields)-1 {
        m.focus++
        cmds := []tea.Cmd{}
        for i := range m.fields {
          if i == m.focus {
            cmds = append(cmds, m.fields[i].input.Focus())
          } else {
            m.fields[i].input.Blur()
          }
        }
        return m, tea.Batch(cmds...)
      }
      if m.action == actRevokeServer || m.action == actRevokeUser {
        nm, cmd := m.submitRevokePass()
        return nm, cmd
      }
      nm, cmd := m.submitForm()
      return nm, cmd
    }
  }
  cmds := []tea.Cmd{}
  for i := range m.fields {
    // only the focused field receives keystrokes; blur only hides the cursor
    if i == m.focus {
      var cmd tea.Cmd
      // split coalesced runes: fast typing (and tmux send-keys) can
      // deliver "up" as one runes message, which textinput's "up"
      // suggestion binding swallows instead of inserting the letters
      if k, isKey := msg.(tea.KeyMsg); isKey && k.Type == tea.KeyRunes && len(k.Runes) > 1 {
        for _, r := range k.Runes {
          m.fields[i].input, cmd = m.fields[i].input.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
          cmds = append(cmds, cmd)
        }
      } else {
        m.fields[i].input, cmd = m.fields[i].input.Update(msg)
        cmds = append(cmds, cmd)
      }
    }
  }
  return m, tea.Batch(cmds...)
}

func (m model) updatePick(msg tea.Msg) (tea.Model, tea.Cmd) {
  key, ok := msg.(tea.KeyMsg)
  if !ok {
    return m, nil
  }
  switch key.String() {
  case "esc":
    m.screen = scrMenu
    return m, nil
  case "up", "k":
    if m.pickIdx > 0 {
      m.pickIdx--
    }
  case "down", "j":
    if m.pickIdx < len(m.picks)-1 {
      m.pickIdx++
    }
  case "enter":
    // single passphrase field, then run
    m.fields = []field{newField("CA passphrase", "", true)}
    m.fields[0].input.Focus()
    m.focus = 0
    m.screen = scrForm
    return m, textinput.Blink
  }
  return m, nil
}

// updateConfirm handles the move-the-CA question shown when a
// settings save changes the CA directory.
func (m model) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
  key, ok := msg.(tea.KeyMsg)
  if !ok {
    return m, nil
  }
  switch key.String() {
  case "esc":
    // back to the settings form, directory field focused
    m.focus = 2
    cmds := []tea.Cmd{}
    for i := range m.fields {
      if i == m.focus {
        cmds = append(cmds, m.fields[i].input.Focus())
      } else {
        m.fields[i].input.Blur()
      }
    }
    m.screen = scrForm
    return m, tea.Batch(cmds...)
  case "up", "k":
    if m.pickIdx > 0 {
      m.pickIdx--
    }
  case "down", "j":
    if m.pickIdx < 1 {
      m.pickIdx++
    }
  case "enter":
    if m.pickIdx == 0 {
      // yes: move the tree, then save the configuration
      m.screen = scrRunning
      return m, func() tea.Msg {
        vals := m.formValues()
        if err := MoveCA(m.moveFrom, m.moveTo); err != nil {
          return doneMsg{err: err}
        }
        orgName, rootCN = vals[0], vals[1]
        baseDir = m.moveTo
        // after baseDir: the entry lands in the CA's new logs dir
        appendLog("moved CA from " + m.moveFrom + " to " + m.moveTo)
        if err := saveConf(); err != nil {
          return doneMsg{err: err}
        }
        return doneMsg{lines: []string{
          "CA moved to " + m.moveTo,
          "",
          "Configuration saved.",
        }}
      }
    }
    // no: keep the CA where it is, save the new location anyway
    vals := m.formValues()
    orgName, rootCN = vals[0], vals[1]
    baseDir = m.moveTo
    if err := saveConf(); err != nil {
      m.showModal(nil, err, scrConfirm)
      return m, nil
    }
    m.showModal([]string{"Configuration saved."}, nil, scrMenu)
    return m, nil
  }
  return m, nil
}

func (m model) renderForm() string {
  var b strings.Builder
  for i, f := range m.fields {
    // blank line between fields, none after the last: the footer
    // owns the spacing before the warnings/help lines
    if i > 0 {
      b.WriteString("\n")
    }
    b.WriteString(f.label + ":\n")
    b.WriteString(f.input.View() + "\n")
  }
  if m.errMsg != "" && !m.modal {
    // indent and word-wrap every line: error text may span multiple
    // lines, and bubbletea truncates anything wider than the terminal
    for _, line := range strings.Split(wrapText(m.errMsg, m.innerWidth()), "\n") {
      b.WriteString(errorStyle.Render(line) + "\n")
    }
    b.WriteString("\n")
  }
  return b.String()
}

func (m model) renderPick() string {
  var b strings.Builder
  kind := "Server"
  if m.action == actRevokeUser {
    kind = "User"
  }
  b.WriteString(kind + " certificates:\n\n")
  for i, p := range m.picks {
    line := "  " + p
    if i == m.pickIdx {
      line = "> " + p
    }
    b.WriteString(m.pickRow(line, i == m.pickIdx) + "\n")
  }
  return b.String()
}

// innerWidth is the usable text width inside the bordered pane.
func (m model) innerWidth() int {
  w := m.width - 6 // 2 border columns + 2-space padding on each side
  if m.width == 0 {
    w = 74
  }
  if w < 20 {
    w = 20
  }
  return w
}

// pickRow renders one selectable row; selected rows are highlighted
// across the full pane width, gp-go style.
func (m model) pickRow(line string, selected bool) string {
  w := m.width - 2 // inner box width
  if m.width == 0 {
    w = 78
  }
  for lipgloss.Width(line) < w {
    line += " "
  }
  if selected {
    return selectedStyle.Render(line)
  }
  return line
}

// frame lays out the full-window screen: header line, a rounded
// bordered pane filling the terminal, then expiry notices and the help
// line below the pane. With the modal open the help line is the
// modal's close hint, not the screen underneath.
func (m model) frame(content, help string) string {
  if m.modal {
    help = " Enter: continue"
  }
  w := m.width
  if w == 0 {
    w = 80
  }
  if w < 20 {
    w = 20
  }
  foot := m.footer(help)
  h := m.height - 4 - strings.Count(foot, "\n") - 1 // header + blank + 2 border rows
  if m.height == 0 {
    h = 19
  }
  if h < 3 {
    h = 3
  }
  box := boxStyle.Width(w-2).Height(h).Render(content)
  return titleStyle.Render(" ca-go "+version) + "\n\n" + box + "\n" + foot
}

// expiryWarnings loads the certificate list and derives the expiry
// warning lines shown on every screen. A CA without issued
// certificates or without a CRL yields no warnings; read errors are
// swallowed so the warnings can never break a screen.
func (m model) expiryWarnings() []string {
  recs, err := ListIssued()
  if err != nil {
    return nil
  }
  return ExpiryNotes(recs)
}

// footer appends the expiry notices and then the screen's help line
// (empty for none). EXPIRING lines render yellow, EXPIRED lines red;
// the layout with notices present is: main text, one empty line,
// notices, one empty line, help line; without, just the help line
// as before.
func (m model) footer(help string) string {
  s := ""
  for _, w := range m.expiryWarnings() {
    style := errorStyle
    if strings.HasPrefix(w, "EXPIRING") {
      style = warnStyle
    }
    for _, line := range strings.Split(wrapText(w, m.innerWidth()), "\n") {
      s += "\n" + style.Render(" "+line)
    }
  }
  if s != "" {
    s += "\n"
  }
  return s + helpStyle.Render(help)
}

// body returns the screen's content and its footer help line.
func (m model) body() (string, string) {
  switch m.screen {
  case scrMenu:
    var b strings.Builder
    for i, item := range menuItems {
      line := "  " + item
      if i == m.menuIdx {
        line = "> " + item
      }
      b.WriteString(m.pickRow(line, i == m.menuIdx) + "\n")
    }
    return b.String(), " ↑/↓ or j/k: move · Enter: select · q or Esc: quit"
  case scrForm:
    return m.renderForm(), " Enter: next/submit · Tab or ↑/↓: next field · Esc: cancel"
  case scrPick:
    return m.renderPick(), " ↑/↓: select · Enter: revoke · Esc: cancel"
  case scrSanity:
    var b strings.Builder
    b.WriteString("CA sanity check found problems:\n\n")
    for i, s := range m.sanity {
      text := s.Msg
      switch s.Kind {
      case "p12":
        // the TUI asks; the CLI report wording stays factual
        text = "PKCS#12 for " + s.Name + " is missing; do you want to regenerate it?  [y/N]"
      case "chain":
        text = "PEM chain for " + s.Name + " is missing; do you want to regenerate it?  [y/N]"
      default:
        text += "  (manual)"
      }
      line := "  " + text
      if i == m.sanIdx {
        line = "> " + text
      }
      b.WriteString(m.pickRow(line, i == m.sanIdx) + "\n")
    }
    return b.String(), " ↑/↓: select · y: fix · N or Enter: skip · Esc or q: continue"
  case scrConfirm:
    var b strings.Builder
    b.WriteString("Move the CA from\n  " + m.moveFrom + "\nto\n  " + m.moveTo + "\n\n")
    options := []string{"Yes, move it", "No, keep it where it is"}
    for i, opt := range options {
      line := "  " + opt
      if i == m.pickIdx {
        line = "> " + opt
      }
      b.WriteString(m.pickRow(line, i == m.pickIdx) + "\n")
    }
    return b.String(), " ↑/↓: select · Enter: confirm · Esc: back to the form"
  case scrRunning:
    return "Working...", ""
  case scrList:
    lines := m.lines
    if m.recs != nil {
      // re-rendered every frame: a resize reshapes the table live
      if len(m.recs) == 0 {
        lines = []string{"No certificates issued yet."}
      } else {
        lines = []string{formatRecordHeader(m.width - 2)}
        for _, r := range m.recs {
          lines = append(lines, formatRecord(r, m.width-2))
        }
      }
    }
    var b strings.Builder
    for _, l := range lines {
      // revoked rows: the whole line red, as they have always been
      allRed := strings.Contains(l, "REVOKED")
      for _, line := range strings.Split(wrapText(l, m.width-2), "\n") {
        // other rows render plain except the trailing status token:
        // Valid green, EXPIRING yellow, EXPIRED red
        if strings.HasPrefix(l, "WARNING") {
          continue // notices come from the shared footer, once per screen
        }
        if allRed {
          b.WriteString(errorStyle.Render(line) + "\n")
          continue
        }
        text, st := line, ""
        tokenStyle := okStyle
        if strings.HasSuffix(line, " Valid") {
          text, st = strings.TrimSuffix(line, " Valid"), "Valid"
        } else if strings.HasSuffix(line, " EXPIRING") {
          text, st = strings.TrimSuffix(line, " EXPIRING"), "EXPIRING"
          tokenStyle = warnStyle
        } else if strings.HasSuffix(line, " EXPIRED") {
          text, st = strings.TrimSuffix(line, " EXPIRED"), "EXPIRED"
          tokenStyle = errorStyle
        }
        out := normalStyle.Render(text)
        if st != "" {
          out += " " + tokenStyle.Render(st)
        }
        b.WriteString(out + "\n")
      }
    }
    return b.String(), " Enter or q: back to menu"
  }
  return "", ""
}

// modalView renders the result overlay centered over the screen behind
// it (gp-go-style modal): issuance and repair output on success, the
// error in red otherwise, with the close hint at the bottom. Errors
// keep a red border so the kind is visible at a glance.
func (m model) modalView(bg string) string {
  w := m.width - 12
  if m.width == 0 {
    w = 60
  }
  if w < 30 {
    w = 30
  }
  var lines []string
  if m.modalErr {
    for _, l := range strings.Split(wrapText("ERROR: "+m.errMsg, w), "\n") {
      lines = append(lines, errorStyle.Render(l))
    }
  } else {
    for _, l := range m.lines {
      // informational notices ("No server certificates to revoke.")
      // render plain; the rest are successes
      style := okStyle
      if strings.HasPrefix(l, "No ") {
        style = normalStyle
      }
      for _, cl := range strings.Split(wrapText(l, w), "\n") {
        lines = append(lines, style.Render(cl))
      }
    }
  }
  lines = append(lines, "", helpStyle.Render("Enter: continue"))
  border := boxStyle
  if m.modalErr {
    border = border.BorderForeground(lipgloss.Color("196"))
  }
  box := border.Render(strings.Join(lines, "\n"))
  return overlayCenter(bg, box, m.width)
}

// overlayCenter stamps box centered over bg. Stamping is ANSI-aware:
// styled bg lines are cut with x/ansi so escape sequences survive.
func overlayCenter(bg, box string, termW int) string {
  bgW := lipgloss.Width(bg)
  if termW > 0 && termW < bgW {
    bgW = termW
  }
  x := (bgW - lipgloss.Width(box)) / 2
  y := (lipgloss.Height(bg) - lipgloss.Height(box)) / 2
  if x < 0 {
    x = 0
  }
  if y < 0 {
    y = 0
  }
  bgLines := strings.Split(bg, "\n")
  boxLines := strings.Split(box, "\n")
  for i, b := range boxLines {
    by := y + i
    if by < 0 || by >= len(bgLines) {
      continue
    }
    left := ansi.Truncate(bgLines[by], x, "")
    bgLines[by] = left + b + ansi.TruncateLeft(bgLines[by], x+lipgloss.Width(b), "")
  }
  return strings.Join(bgLines, "\n")
}

func (m model) View() string {
  content, help := m.body()
  base := m.frame(content, help)
  if !m.modal {
    return base
  }
  return m.modalView(base)
}
