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

// ca-go - CA manager: Go TUI front end and CA engine.
//
// Run without arguments for the TUI (operates on the configured CA
// directory, default ~/ca-go), or use the CLI subcommands for scripting
// (passwords via environment variables, never on the command line):
//
//   ca-go new-ca                        CAGO_ROOT_PASS
//   ca-go server <fqdn>                 CAGO_ROOT_PASS, CAGO_P12_PASS (optional)
//   ca-go user <cn> <email>             CAGO_USER_PASS, CAGO_ROOT_PASS, CAGO_P12_PASS (optional)
//   ca-go revoke-server <fqdn>          CAGO_ROOT_PASS
//   ca-go revoke-user <email>           CAGO_ROOT_PASS
//   ca-go crl                           CAGO_ROOT_PASS
//   ca-go show
//   ca-go version
//
// Settings (CA directory, organization, CA subject names)
// live in ~/.config/ca-go/ca-go.conf; on first run the TUI asks for them.

import (
  "fmt"
  "os"

  tea "github.com/charmbracelet/bubbletea"
)

var version = "v1.0.0"

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
  case "version":
    fmt.Println(version)
    return
  case "new-ca":
    _, err = NewCA(os.Getenv(envRootPass))
  case "server":
    need(len(args) == 2, "usage: ca-go server <fqdn>")
    _, err = IssueServer(args[1], os.Getenv(envRootPass), os.Getenv(envP12Pass))
  case "user":
    need(len(args) == 3, "usage: ca-go user <cn> <email>")
    _, err = IssueUser(args[1], args[2], os.Getenv(envUserPass), os.Getenv(envRootPass), os.Getenv(envP12Pass))
  case "revoke-server":
    need(len(args) == 2, "usage: ca-go revoke-server <fqdn>")
    _, err = Revoke("server", args[1], os.Getenv(envRootPass))
  case "revoke-user":
    need(len(args) == 2, "usage: ca-go revoke-user <email>")
    _, err = Revoke("user", args[1], os.Getenv(envRootPass))
  case "crl":
    _, err = RegenerateCRL(os.Getenv(envRootPass))
  case "show":
    recs, e := ListIssued()
    if e != nil {
      fail(e)
    }
    if len(recs) == 0 {
      fmt.Println("No certificates issued yet.")
      return
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
    fmt.Println("             revoke-server <fqdn> | revoke-user <email> | crl | show | version]")
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
