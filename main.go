package main

// ca-go - CA manager: Go TUI front end and CA engine.
//
// Run without arguments for the TUI (operates on the configured CA
// directory, default ~/ca-go), or use the CLI subcommands for scripting
// (passwords via environment variables, never on the command line):
//
//   ca-go new-ca                        CAGO_ROOT_PASS, CAGO_SIGN_PASS
//   ca-go server <fqdn>                 CAGO_SIGN_PASS, CAGO_P12_PASS (optional)
//   ca-go user <cn> <email>             CAGO_USER_PASS, CAGO_SIGN_PASS, CAGO_P12_PASS (optional)
//   ca-go revoke-server <fqdn>          CAGO_SIGN_PASS
//   ca-go revoke-user <email>           CAGO_SIGN_PASS
//   ca-go crl                           CAGO_SIGN_PASS
//   ca-go show
//
// Settings (CA directory, organization, CA subject names)
// live in ~/.config/ca-go/ca-go.conf; on first run the TUI asks for them.

import (
  "fmt"
  "os"

  tea "github.com/charmbracelet/bubbletea"
)

func fail(err error) {
  fmt.Fprintln(os.Stderr, "ERROR:", err)
  os.Exit(1)
}

func main() {
  if err := loadConf(); err != nil {
    fail(err)
  }
  args := os.Args[1:]
  if len(args) == 0 {
    p := tea.NewProgram(initialModel(), tea.WithAltScreen())
    if _, err := p.Run(); err != nil {
      fail(err)
    }
    return
  }

  var err error
  switch args[0] {
  case "new-ca":
    _, err = NewCA(os.Getenv(envRootPass), os.Getenv(envSignPass))
  case "server":
    need(len(args) == 2, "usage: ca-go server <fqdn>")
    _, err = IssueServer(args[1], os.Getenv(envSignPass), os.Getenv(envP12Pass))
  case "user":
    need(len(args) == 3, "usage: ca-go user <cn> <email>")
    _, err = IssueUser(args[1], args[2], os.Getenv(envUserPass), os.Getenv(envSignPass), os.Getenv(envP12Pass))
  case "revoke-server":
    need(len(args) == 2, "usage: ca-go revoke-server <fqdn>")
    _, err = Revoke("server", args[1], os.Getenv(envSignPass))
  case "revoke-user":
    need(len(args) == 2, "usage: ca-go revoke-user <email>")
    _, err = Revoke("user", args[1], os.Getenv(envSignPass))
  case "crl":
    _, err = RegenerateCRL(os.Getenv(envSignPass))
  case "show":
    recs, e := ListIssued()
    if e != nil {
      fail(e)
    }
    for _, r := range recs {
      status := "valid"
      if r.Revoked {
        status = "REVOKED"
      }
      fmt.Printf("%-7s %-28s %-20s expires %s [%s]\n",
        r.Kind, r.Name, r.CommonName, r.NotAfter.Format("2006-01-02"), status)
    }
    return
  default:
    fmt.Println("usage: ca-go [new-ca | server <fqdn> | user <cn> <email> |")
    fmt.Println("             revoke-server <fqdn> | revoke-user <email> | crl | show]")
    os.Exit(2)
  }
  if err != nil {
    fail(err)
  }
}

func need(cond bool, msg string) {
  if !cond {
    fmt.Fprintln(os.Stderr, msg)
    os.Exit(2)
  }
}
