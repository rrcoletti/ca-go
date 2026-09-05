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

//go:build windows

package main

import "os"

// No advisory locking on windows; the lock file still serializes within
// reason for the single-user homelab use case.

func lockState() (*os.File, error) {
  return os.OpenFile(stateLockPath(), os.O_CREATE|os.O_RDWR, 0600)
}

func unlockState(f *os.File) {
  f.Close()
}
