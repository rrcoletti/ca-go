# ca-go

A small certificate authority manager for your homelab or private network. It issues server and user certificates, keeps a revocation list and runs in the terminal (TUI when started with no arguments or plain CLI subcommands for scripts).

The whole CA is files in a directory. Nothing else to install (no database, no daemon, etc).

## What it does

- Creates the root CA (ECDSA P-256, ten years) and an empty CRL
- Issues server certificates and user certificates (S/MIME email protection + client auth), valid two years
- Revokes certificates and regenerates the CRL (90-day window)
- Exports PKCS#12 bundles for browsers and mail clients
- Passphrase encrypts the root and user keys as PKCS#8 (AES-256). Server keys stay unencrypted so services can load them without a passphrase
- All certificate work uses the Go standard library
- The `openssl` binary is called only for what Go does not support (writing encrypted PKCS#8 keys and exporting PKCS#12)
- Every openssl failure is logged to `logs/ca-go.log`

## Building

Two things required: Go (1.23 or newer) and `openssl` on your PATH. The build is pure Go, so no C compiler.

**Linux:** Install Go and OpenSSL from your package manager, for example:

    # Debian / Ubuntu
    sudo apt install golang-go openssl

    # Fedora
    sudo dnf install golang openssl

    # Arch
    sudo pacman -S go openssl

Obs: Distro Go packages can lag behind. If yours is older than 1.23, grab the latest from [go.dev/dl](https://go.dev/dl/) instead.

**macOS:** Install both with Homebrew:

    brew install go openssl

Obs: macOS ships its own `openssl` at `/usr/bin/openssl`, but it's LibreSSL. Homebrew does not put its OpenSSL on your PATH by default. Check with `openssl version`, if it does not say OpenSSL 3, put the Homebrew one first in your PATH:

    export PATH="$(brew --prefix openssl@3)/bin:$PATH"

Then build:

    git clone https://github.com/rrcoletti/ca-go.git
    cd ca-go
    go build

That produces the `ca-go` binary. Run `openssl version` once before your first CA, if you are unsure what is on your PATH. Anything showing OpenSSL 3.x works, while older 1.x versions and LibreSSL might work too (considered it unsupported for ca-go). OpenSSL 3.x is what ca-go is tested against.

## First run

Start the TUI with no arguments:

    ./ca-go

On the first run, it'll ask for three things:

- Organization, which goes into every cert subject
- Root CA common name (CN)
- The directory where the CA lives (default `~/ca-go`)

These are saved to `~/.config/ca-go/ca-go.conf`, which looks like this:

    # ca-go configuration
    dir = /home/you/ca-go
    org = Example
    rootCN = Example Root CA

You can edit the file directly or use the **Edit configuration** option in the menu at any time, but if the CA on disk disagrees with the values you enter, ca-go refuses to save any files and tells you exactly which field differs.

## Creating a CA

Pick **New CA** in the menu (or run `ca-go new-ca`) and choose the CA passphrase. It is typed twice, that is the **only passphrase that matters!!!** Every cert, every revoke, every CRL regeneration asks for it. If you lose it, the key is unreadable. You'll have to start over with a new CA and reissue all certs.

## Issuing certificates

**New server certificate** asks for a FQDN and the CA passphrase. The key is written unencrypted next to the cert, which is what most services expect. Point your service at `servers/keys/<fqdn>.key` and `servers/certs/<fqdn>-chain.pem` and import `ca-root/certs/root-ca.crt` into whatever needs to trust your CA.

**New user certificate** asks for a name, an email, a passphrase for the user's key, the CA passphrase and an optional p12 passphrase. The user gets an encrypted key and a PKCS#12 bundle (cert plus chain) to import into a browser or mail client. Leave the p12 passphrase empty if you do not want one on the bundle.

## Revoking

**Revoke server/user certificate** shows the list of valid certificates, pick one, enter the CA passphrase and it's done.

ca-go writes the CRL to `ca-root/crls/root-ca.crl`, distributing it to clients is up to you.

## CLI

Every TUI action has a scripting equivalent. Passwords go through environment variables, never argv, so they do not show up in `ps` output:

    ca-go new-ca                    # CAGO_ROOT_PASS
    ca-go server <fqdn>             # CAGO_ROOT_PASS, CAGO_P12_PASS (optional)
    ca-go user <cn> <email>         # CAGO_USER_PASS, CAGO_ROOT_PASS, CAGO_P12_PASS (optional)
    ca-go revoke-server <fqdn>      # CAGO_ROOT_PASS
    ca-go revoke-user <email>       # CAGO_ROOT_PASS
    ca-go crl                       # CAGO_ROOT_PASS
    ca-go show

`ca-go show` prints one line per certificate, revoked ones included:

    server  host.example.com   host.example.com   expires 2028-09-03 [valid]
    user    user@example.com   User Name          expires 2028-09-03 [REVOKED]

## What lives on disk

Everything lives under the configured directory (`~/ca-go` unless you changed it):

    ca-root/keys/root-ca.key       encrypted root key
    ca-root/certs/root-ca.crt      root cert
    ca-root/crls/root-ca.crl       current CRL
    servers/keys|csrs|certs|p12/   one subdirectory per artifact kind
    users/keys|csrs|certs|p12/
    logs/ca-go.log                 openssl output, one timestamped block per run
    state.json                     serial and revocation bookkeeping
    state.lock                     cross-process lock for state updates

Each issued cert also gets a `<name>-chain.pem` with two certs... the leaf and the root. No private keys end up in any chain file!

Keys and the state file are written with mode 0600, directories with 0700. Bookkeeping updates are locked and written atomically, so running a CLI command while the TUI is open will not corrupt anything.

## Things worth knowing

- Your CA directory is the whole CA. Back it up and keep it private. Anyone with the root key and its passphrase can issue certs that your machines will trust.
- An empty p12 passphrase means an unencrypted PKCS#12. Fine for testing, risky for real user credentials.
- Revoked artifacts stay on disk with mode 000 until you remove or archive them.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) for more details.
