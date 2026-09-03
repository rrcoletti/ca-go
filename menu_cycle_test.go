package main

import (
  "testing"

  tea "github.com/charmbracelet/bubbletea"
)

func TestMenuCyclesUp(t *testing.T) {
  m := initialModel() // selection on "New CA" (first item)
  next, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
  m2 := next.(model)
  if m2.menuIdx != len(menuItems)-1 {
    t.Fatalf("up from first item should wrap to last, got index %d (%s)",
      m2.menuIdx, menuItems[m2.menuIdx])
  }
  if menuItems[m2.menuIdx] != "Quit" {
    t.Fatalf("expected Quit, got %s", menuItems[m2.menuIdx])
  }
  // and down from there wraps back to the first
  next, _ = m2.Update(tea.KeyMsg{Type: tea.KeyDown})
  m3 := next.(model)
  if m3.menuIdx != 0 {
    t.Fatalf("down from last should wrap to first, got %d", m3.menuIdx)
  }
}
