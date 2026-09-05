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
