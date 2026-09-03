package main

// Casinha CA Manager v1.0 - Go TUI front end and CA engine.
//
// Run without arguments for the TUI (operates on the current directory),
// or use the CLI subcommands for scripting (passwords via environment
// variables, never on the command line):
//
//   ca-go new-ca                        ROOT_PASS, SIGN_PASS
//   ca-go server <fqdn>                 SIGN_PASS, P12_PASS (optional)
//   ca-go user <cn> <email>             USER_PASS, SIGN_PASS, P12_PASS (optional)
//   ca-go revoke-server <fqdn>          SIGN_PASS
//   ca-go revoke-user <email>           SIGN_PASS
//   ca-go crl                           SIGN_PASS
//   ca-go show

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
		_, err = NewCA(os.Getenv("ROOT_PASS"), os.Getenv("SIGN_PASS"))
	case "server":
		need(len(args) == 2, "usage: ca-go server <fqdn>")
		_, err = IssueServer(args[1], os.Getenv("SIGN_PASS"), os.Getenv("P12_PASS"))
	case "user":
		need(len(args) == 3, "usage: ca-go user <cn> <email>")
		_, err = IssueUser(args[1], args[2], os.Getenv("USER_PASS"), os.Getenv("SIGN_PASS"), os.Getenv("P12_PASS"))
	case "revoke-server":
		need(len(args) == 2, "usage: ca-go revoke-server <fqdn>")
		_, err = Revoke("server", args[1], os.Getenv("SIGN_PASS"))
	case "revoke-user":
		need(len(args) == 2, "usage: ca-go revoke-user <email>")
		_, err = Revoke("user", args[1], os.Getenv("SIGN_PASS"))
	case "crl":
		_, err = RegenerateCRL(os.Getenv("SIGN_PASS"))
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
			fmt.Printf("%-7s %-28s expires %s [%s]\n",
				r.Kind, r.Name, r.NotAfter.Format("2006-01-02"), status)
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
