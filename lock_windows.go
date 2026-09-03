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
