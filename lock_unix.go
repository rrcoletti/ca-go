//go:build !windows

package main

// Cross-process lock protecting state.json read-modify-write cycles.

import (
  "os"
  "syscall"
)

func lockState() (*os.File, error) {
  f, err := os.OpenFile(stateLockPath, os.O_CREATE|os.O_RDWR, 0600)
  if err != nil {
    return nil, err
  }
  if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
    f.Close()
    return nil, err
  }
  return f, nil
}

func unlockState(f *os.File) {
  syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
  f.Close()
}
