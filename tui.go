package main

// TUI built on Bubble Tea. Arrow keys/vi keys to navigate, Enter to select,
// Esc to cancel a form, q on the menu to quit.

import (
  "fmt"
  "os"
  "strings"

  "github.com/charmbracelet/bubbles/textinput"
  tea "github.com/charmbracelet/bubbletea"
  "github.com/charmbracelet/lipgloss"
)

type screen int

const (
  scrMenu screen = iota
  scrForm
  scrPick
  scrRunning
  scrResult
  scrList
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
)

var menuItems = []string{
  "New CA",
  "Regenerate CRL",
  "New server certificate",
  "Revoke server certificate",
  "New user certificate",
  "Revoke user certificate",
  "Show issued certificates",
  "Quit",
}

var (
  titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
  selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
  normalStyle   = lipgloss.NewStyle()
  errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
  okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
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
  errMsg  string
}

func initialModel() model {
  return model{screen: scrMenu}
}

func newField(label, placeholder string, masked bool) field {
  ti := textinput.New()
  ti.Placeholder = placeholder
  ti.CharLimit = 128
  ti.Width = 40
  if masked {
    ti.EchoMode = textinput.EchoPassword
  }
  ti.Focus()
  return field{label: label, input: ti}
}

// form definitions per action
func (m model) startForm(act action) (tea.Model, tea.Cmd) {
  m.screen = scrForm
  m.action = act
  m.focus = 0
  m.fields = nil
  m.errMsg = ""
  cmds := []tea.Cmd{}
  add := func(label, placeholder string, masked bool) {
    f := newField(label, placeholder, masked)
    m.fields = append(m.fields, f)
    cmds = append(cmds, textinput.Blink)
  }
  switch act {
  case actNewCA:
    add("Root CA passphrase", "", true)
    add("Confirm root passphrase", "", true)
    add("Signing CA passphrase", "", true)
    add("Confirm signing passphrase", "", true)
  case actCRL:
    add("Signing CA passphrase", "", true)
  case actServer:
    add("FQDN (e.g. dock.casinha.wro)", "", false)
    add("Signing CA passphrase", "", true)
    add("p12 export passphrase (empty = none)", "", true)
  case actUser:
    add("Common name (e.g. rcoletti)", "", false)
    add("Email (name@domain)", "", false)
    add("User passphrase", "", true)
    add("Confirm user passphrase", "", true)
    add("Signing CA passphrase", "", true)
    add("p12 export passphrase (empty = none)", "", true)
  case actRevokeServer, actRevokeUser:
    kind := "server"
    if act == actRevokeUser {
      kind = "user"
    }
    recs, err := ListIssued()
    if err != nil {
      m.screen = scrResult
      m.errMsg = err.Error()
      return m, nil
    }
    m.picks = nil
    for _, r := range recs {
      if r.Kind == kind && !r.Revoked {
        m.picks = append(m.picks, r.Name)
      }
    }
    if len(m.picks) == 0 {
      m.screen = scrResult
      m.lines = []string{"No " + kind + " certificates to revoke."}
      return m, nil
    }
    if len(m.picks) == 1 {
      // single candidate: go straight to passphrase
      add("Signing CA passphrase", "", true)
      m.screen = scrForm
      return m, textinput.Blink
    }
    m.pickIdx = 0
    m.screen = scrPick
    return m, nil
  }
  return m, tea.Batch(cmds...)
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
    if vals[0] == "" || vals[2] == "" {
      m.errMsg = "passphrases must not be empty"
      return m, nil
    }
    if vals[0] != vals[1] {
      m.errMsg = "root passphrases do not match"
      return m, nil
    }
    if vals[2] != vals[3] {
      m.errMsg = "signing passphrases do not match"
      return m, nil
    }
  }
  if act == actUser {
    if vals[0] == "" {
      m.errMsg = "common name must not be empty"
      return m, nil
    }
    if !validEmail(vals[1]) {
      m.errMsg = "email must be in the format name@domain"
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
  if act == actServer && vals[0] == "" {
    m.errMsg = "fqdn must not be empty"
    return m, nil
  }

  m.screen = scrRunning
  m.errMsg = ""
  return m, func() tea.Msg {
    var lines []string
    var err error
    switch act {
    case actNewCA:
      lines, err = NewCA(vals[0], vals[2])
    case actCRL:
      lines, err = RegenerateCRL(vals[0])
    case actServer:
      lines, err = IssueServer(vals[0], vals[1], vals[2])
    case actUser:
      lines, err = IssueUser(vals[0], vals[1], vals[2], vals[4], vals[5])
    }
    return doneMsg{lines: lines, err: err}
  }
}

// revokeNeedsPass returns the revoke passphrase index (the only field)
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
  m.screen = scrRunning
  return m, func() tea.Msg {
    lines, err := Revoke(kind, name, vals[0])
    return doneMsg{lines: lines, err: err}
  }
}

func (m model) Init() tea.Cmd {
  return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
  switch msg := msg.(type) {
  case tea.KeyMsg:
    switch msg.String() {
    case "ctrl+c":
      return m, tea.Quit
    }
    switch m.screen {
    case scrMenu:
      return m.updateMenu(msg)
    case scrForm:
      return m.updateForm(msg)
    case scrPick:
      return m.updatePick(msg)
    case scrResult:
      switch msg.String() {
      case "enter", "esc", "q":
        m.screen = scrMenu
        m.lines = nil
        m.errMsg = ""
        return m, nil
      }
    case scrList:
      switch msg.String() {
      case "enter", "esc", "q":
        m.screen = scrMenu
        return m, nil
      }
    }
  case doneMsg:
    m.screen = scrResult
    m.lines = msg.lines
    if msg.err != nil {
      m.errMsg = msg.err.Error()
    }
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
    switch action(m.menuIdx) {
    case actShow:
      recs, err := ListIssued()
      m.lines = nil
      if err != nil {
        m.errMsg = err.Error()
      } else {
        for _, r := range recs {
          status := "valid"
          if r.Revoked {
            status = "REVOKED"
          }
          m.lines = append(m.lines, fmt.Sprintf("%-7s %-28s expires %s [%s]",
            r.Kind, r.Name, r.NotAfter.Format("2006-01-02"), status))
        }
        if len(m.lines) == 0 {
          m.lines = []string{"No certificates issued yet."}
        }
      }
      m.screen = scrList
      return m, nil
    }
    if m.menuIdx == len(menuItems)-1 { // Quit
      return m, tea.Quit
    }
    // New CA / CRL / server / user / revokes -> forms or pick
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
    }
    if act == actNewCA {
      if _, err := os.Stat(signCertPath); err == nil {
        m.screen = scrResult
        m.errMsg = "CA already exists in this directory"
        return m, nil
      }
    }
    return m.startForm(act)
  case "q":
    return m, tea.Quit
  }
  return m, nil
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
  if key, ok := msg.(tea.KeyMsg); ok {
    switch key.String() {
    case "esc":
      m.screen = scrMenu
      m.errMsg = ""
      return m, nil
    case "tab", "shift+tab", "down", "up":
      // move focus
      s := key.String()
      if s == "tab" || s == "down" {
        m.focus = (m.focus + 1) % len(m.fields)
      } else {
        m.focus = (m.focus - 1 + len(m.fields)) % len(m.fields)
      }
      cmds := []tea.Cmd{}
      for i := range m.fields {
        if i == m.focus {
          cmds = append(cmds, m.fields[i].input.Focus())
        } else {
          m.fields[i].input.Blur()
        }
      }
      m.errMsg = ""
      return m, tea.Batch(cmds...)
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
      m.fields[i].input, cmd = m.fields[i].input.Update(msg)
      cmds = append(cmds, cmd)
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
    m.fields = []field{newField("Signing CA passphrase", "", true)}
    m.focus = 0
    m.screen = scrForm
    return m, textinput.Blink
  }
  return m, nil
}

func (m model) renderForm() string {
  var b strings.Builder
  for i, f := range m.fields {
    cursor := "  "
    if i == m.focus {
      cursor = "> "
    }
    b.WriteString(cursor + f.label + ":\n")
    b.WriteString("   " + f.input.View() + "\n\n")
  }
  if m.errMsg != "" {
    b.WriteString(errorStyle.Render("  "+m.errMsg) + "\n\n")
  }
  b.WriteString(helpStyle.Render("  Enter: next/submit · Tab: next field · Esc: cancel"))
  return b.String()
}

func (m model) renderPick() string {
  var b strings.Builder
  b.WriteString("  Available certificates:\n\n")
  for i, p := range m.picks {
    cursor := "    "
    style := normalStyle
    if i == m.pickIdx {
      cursor = "  > "
      style = selectedStyle
    }
    b.WriteString(style.Render(cursor+p) + "\n")
  }
  b.WriteString("\n" + helpStyle.Render("  ↑/↓: select · Enter: revoke · Esc: cancel"))
  return b.String()
}

// frame renders the title and the screen content.
func (m model) frame(content string) string {
  return titleStyle.Render("Casinha CA Manager") + "\n\n" + content
}

func (m model) View() string {
  body := ""
  switch m.screen {
  case scrMenu:
    body = "\n"
    for i, item := range menuItems {
      cursor := "    "
      style := normalStyle
      if i == m.menuIdx {
        cursor = "  > "
        style = selectedStyle
      }
      body += style.Render(cursor+item) + "\n"
    }
    body += "\n" + helpStyle.Render("  ↑/↓ or j/k: move · Enter: select · q: quit")
  case scrForm:
    body = m.renderForm()
  case scrPick:
    body = m.renderPick()
  case scrRunning:
    body = "  Working..."
  case scrResult:
    for _, l := range m.lines {
      body += "  " + okStyle.Render(l) + "\n"
    }
    if m.errMsg != "" {
      body += "\n  " + errorStyle.Render("ERROR: "+m.errMsg)
    }
    body += "\n" + helpStyle.Render("  Enter or q: back to menu")
  case scrList:
    for _, l := range m.lines {
      style := normalStyle
      if strings.Contains(l, "REVOKED") {
        style = errorStyle
      }
      body += "  " + style.Render(l) + "\n"
    }
    body += "\n" + helpStyle.Render("  Enter or q: back to menu")
  }
  return m.frame(body)
}
