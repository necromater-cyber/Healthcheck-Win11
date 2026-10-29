package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCountSections(t *testing.T) {
	if n := countSections(windowsScript); n < 30 {
		t.Errorf("windows sections = %d, want >= 30", n)
	}
	if n := countSections(outlookScript); n < 10 {
		t.Errorf("outlook sections = %d, want >= 10", n)
	}
}

func TestFmtElapsed(t *testing.T) {
	cases := map[time.Duration]string{
		4 * time.Second:                       "4s",
		112 * time.Second:                     "1m 52s",
		59*time.Second + 600*time.Millisecond: "1m 00s",
	}
	for d, want := range cases {
		if got := fmtElapsed(d); got != want {
			t.Errorf("fmtElapsed(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestFlagTotals(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.md")
	os.WriteFile(p, []byte("x\nFlag totals: ACTION=2  ACTION - CRITICAL=1  INFO=7  OK=24  WATCH=6\ny"), 0o600)
	m := readFlagTotals(p)
	if m["ACTION"] != "2" || m["ACTION - CRITICAL"] != "1" || m["OK"] != "24" || m["WATCH"] != "6" {
		t.Errorf("parsed %v", m)
	}
	if got := renderFlags(m); !strings.Contains(got, "24 OK") || !strings.Contains(got, "1 CRITICAL") {
		t.Errorf("render = %q", got)
	}
}

func TestPlainModeHasNoEscapes(t *testing.T) {
	ui.color = false
	for _, s := range []string{bold("x"), dim("x"), red("x"), glyph("✔", "[ok]")} {
		if strings.Contains(s, "\x1b") || strings.ContainsRune(s, '✔') {
			t.Errorf("plain output contains rich characters: %q", s)
		}
	}
}

func TestUIWriterCountsSections(t *testing.T) {
	ui.color = true
	defer func() { ui.color = false }()
	p := &progress{total: 5} // not live: no goroutine, no drawing
	w := &uiWriter{capt: &pathCapture{}, prog: p}
	w.Write([]byte("Windows 11 Health Collector\n  -> 01. OS\n  -> 02. Hardware\r\nPartial"))
	w.Write([]byte(" line\n  -> 03. Volumes\n"))
	if p.n != 3 || p.title != "03. Volumes" {
		t.Errorf("progress n=%d title=%q", p.n, p.title)
	}
}

func TestPathsStillCapturedInRichMode(t *testing.T) {
	ui.color = true
	defer func() { ui.color = false }()
	c := &pathCapture{}
	w := &uiWriter{capt: c, prog: &progress{}}
	w.Write([]byte(`  C:\Users\U\Desktop\HealthReport_PC_20261027-1_part1of3.md  (40 KB)` + "\n"))
	if got := c.Paths(); len(got) != 1 {
		t.Errorf("paths = %v", got)
	}
}
