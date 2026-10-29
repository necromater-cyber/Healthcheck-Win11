package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEmbeddedScripts(t *testing.T) {
	for name, b := range map[string][]byte{winScriptName: windowsScript, olScriptName: outlookScript} {
		if len(b) < 10000 {
			t.Errorf("%s looks truncated: %d bytes", name, len(b))
		}
		if !bytes.Contains(b, []byte("param(")) || !bytes.Contains(b, []byte("=== BEGIN COLLECTED DATA ===")) {
			t.Errorf("%s is missing expected markers", name)
		}
	}
	// Every parameter the launcher passes must exist in the script's param block.
	win := string(windowsScript)
	for _, p := range []string{"$DaysBack", "$OutputFolder", "$Verbosity", "$MaxUptimeDays", "$SplitOutput",
		"$MaxPartKB", "$MaxParts", "$IncludeIntegrityScan", "$IncludeBatteryReport", "$SkipAdminCheck"} {
		if !strings.Contains(win, p) {
			t.Errorf("Windows script has no %s parameter", p)
		}
	}
	ol := string(outlookScript)
	for _, p := range []string{"$DaysBack", "$OutputFolder", "$DeepFolderScan", "$AdditionalEndpoints",
		"$FolderWarnThreshold", "$FolderActionThreshold"} {
		if !strings.Contains(ol, p) {
			t.Errorf("Outlook script has no %s parameter", p)
		}
	}
}

func TestBuildWindowsArgs(t *testing.T) {
	got := buildWindowsArgs(winOpts{copilot: true})
	want := []string{"-SkipAdminCheck", "-DaysBack", "3", "-Verbosity", "Compact", "-SplitOutput", "-MaxPartKB", "40", "-MaxParts", "3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("copilot preset\n got %v\nwant %v", got, want)
	}
	// explicit flags override the preset
	got = buildWindowsArgs(winOpts{copilot: true, days: 10, verbosity: "Full", maxPartKB: 80, out: `C:\Reports Dir`})
	want = []string{"-SkipAdminCheck", "-DaysBack", "10", "-OutputFolder", `C:\Reports Dir`, "-Verbosity", "Full", "-SplitOutput", "-MaxPartKB", "80", "-MaxParts", "3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("override\n got %v\nwant %v", got, want)
	}
	if got = buildWindowsArgs(winOpts{}); !reflect.DeepEqual(got, []string{"-SkipAdminCheck"}) {
		t.Errorf("defaults should pass only -SkipAdminCheck, got %v", got)
	}
	got = buildWindowsArgs(winOpts{integrity: true, battery: true, maxUptime: 14, raw: []string{"-DetailEventCount", "10"}})
	want = []string{"-SkipAdminCheck", "-MaxUptimeDays", "14", "-IncludeIntegrityScan", "-IncludeBatteryReport", "-DetailEventCount", "10"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("switches/raw\n got %v\nwant %v", got, want)
	}
}

func TestBuildOutlookArgs(t *testing.T) {
	got := buildOutlookArgs(olOpts{deep: true, endpoints: stringList{"mail.contoso.com", "autodiscover.contoso.com"}, warn: 30000})
	want := []string{"-DeepFolderScan", "-AdditionalEndpoints", "mail.contoso.com,autodiscover.contoso.com", "-FolderWarnThreshold", "30000"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	if got = buildOutlookArgs(olOpts{}); len(got) != 0 {
		t.Errorf("defaults should pass nothing, got %v", got)
	}
}

func TestParsingAndValidation(t *testing.T) {
	if _, err := parseWindows([]string{"--days", "400"}); err == nil {
		t.Error("expected error for --days 400")
	}
	if _, err := parseWindows([]string{"--max-uptime-days", "100"}); err == nil {
		t.Error("expected error for --max-uptime-days 100")
	}
	if _, err := parseWindows([]string{"--max-part-kb", "5"}); err == nil {
		t.Error("expected error for --max-part-kb 5")
	}
	if _, err := parseWindows([]string{"--verbosity", "loud"}); err == nil {
		t.Error("expected error for bad verbosity")
	}
	o, err := parseWindows([]string{"--verbosity", "COMPACT", "--split", "--", "-DetailEventCount", "10"})
	if err != nil || o.verbosity != "Compact" || !o.split || !reflect.DeepEqual(o.raw, []string{"-DetailEventCount", "10"}) {
		t.Errorf("unexpected parse result %+v err=%v", o, err)
	}
	if _, err := parseOutlook([]string{"--days", "91"}); err == nil {
		t.Error("expected error for outlook --days 91")
	}
	ol, err := parseOutlook([]string{"--endpoint", "a.example", "--endpoint", "b.example"})
	if err != nil || len(ol.endpoints) != 2 {
		t.Errorf("repeatable --endpoint failed: %+v err=%v", ol, err)
	}
	if _, err := parseAll([]string{"--days", "100"}); err == nil {
		t.Error("expected error for all --days 100")
	}
}

func TestSplitRaw(t *testing.T) {
	own, raw := splitRaw([]string{"--days", "3", "--", "-X", "1"})
	if !reflect.DeepEqual(own, []string{"--days", "3"}) || !reflect.DeepEqual(raw, []string{"-X", "1"}) {
		t.Errorf("own=%v raw=%v", own, raw)
	}
	own, raw = splitRaw([]string{"--days", "3"})
	if len(own) != 2 || raw != nil {
		t.Errorf("own=%v raw=%v", own, raw)
	}
}

func TestPathCapture(t *testing.T) {
	var c pathCapture
	c.Write([]byte("Done in 41.2 seconds.\r\n"))
	c.Write([]byte("  C:\\Users\\Jo Smith\\Desktop\\HealthReport_PC1_20261027-080000_part1of2.md  (38.1 KB)\r\n"))
	c.Write([]byte("  C:\\Users\\Jo Smith\\Desktop\\HealthReport_PC1_20261027-080000_part2of2.md  (35.0 KB)\r\n"))
	c.Write([]byte("Report: D:\\out\\OutlookHealthReport_PC1_20261027-080100.md  (60 KB)\r\n"))
	c.Write([]byte("Report: D:\\out\\OutlookHealthReport_PC1_20261027-080100.md  (60 KB)\r\n")) // duplicate
	got := c.Paths()
	if len(got) != 3 {
		t.Fatalf("expected 3 unique paths, got %d: %v", len(got), got)
	}
	if !strings.HasSuffix(got[0], "part1of2.md") || !strings.HasSuffix(got[2], "080100.md") {
		t.Errorf("unexpected paths %v", got)
	}
}

func TestWriteScriptAddsBOMOnce(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.ps1")
	if err := writeScript(p, []byte("Write-Host hi")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) || bytes.Count(b, []byte{0xEF, 0xBB, 0xBF}) != 1 {
		t.Error("expected exactly one UTF-8 BOM")
	}
	if err := writeScript(p, b); err != nil { // already has BOM: must not double it
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(p)
	if bytes.Count(b2, []byte{0xEF, 0xBB, 0xBF}) != 1 {
		t.Error("BOM was duplicated")
	}
}

func TestDispatchUnknownAndHelp(t *testing.T) {
	if rc := dispatch([]string{"bogus"}); rc != 2 {
		t.Errorf("unknown command rc=%d, want 2", rc)
	}
	if rc := dispatch([]string{"help"}); rc != 0 {
		t.Errorf("help rc=%d", rc)
	}
	if rc := dispatch([]string{"version"}); rc != 0 {
		t.Errorf("version rc=%d", rc)
	}
}

func TestCollectorVersionParsed(t *testing.T) {
	if v := collectorVersion(windowsScript); v == "?" {
		t.Error("windows collector version not found in embedded script")
	}
	if v := collectorVersion(outlookScript); v == "?" {
		t.Error("outlook collector version not found in embedded script")
	}
}
