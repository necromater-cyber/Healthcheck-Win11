package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testID = identity{Host: "DESKTOP-5OCD5RH", User: "andrew", Domain: "CONTOSO", DNSDomain: "corp.contoso.com", ProfileDir: "andrew"}

func rd(s string) string { return newRedactor(testID).Redact(s) }

func TestRedactHostUserDomain(t *testing.T) {
	r := newRedactor(testID)
	in := "Host DESKTOP-5OCD5RH\n" + `C:\Users\andrew\AppData\x.dmp` + "\n" + `CONTOSO\andrew` + " logged on; contoso is the domain; srv.corp.contoso.com\nfile HealthReport_desktop-5ocd5rh_2026.md"
	out := r.Redact(in)
	for _, bad := range []string{"DESKTOP-5OCD5RH", "andrew", "CONTOSO", "corp.contoso.com", "desktop-5ocd5rh"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
			t.Errorf("%q survived: %s", bad, out)
		}
	}
	for _, want := range []string{"HOST-1", `\Users\USER-1\`, `DOMAIN-1\USER-1`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
}

func TestRedactStable(t *testing.T) {
	r := newRedactor(testID)
	a := r.Redact("10.1.2.3 and 10.1.2.4")
	b := r.Redact("again 10.1.2.3")
	if !strings.Contains(a, "IP-PRIV-1 and IP-PRIV-2") || !strings.Contains(b, "IP-PRIV-1") {
		t.Errorf("not stable: %q / %q", a, b)
	}
}

func TestRedactKeepsNonAddresses(t *testing.T) {
	keep := []string{
		"Windows 10.0.26100.1 build", "Driver version 31.0.12044.1", "mask 255.255.255.0", "loopback 127.0.0.1",
		"ping 8.8.8.8 and 1.1.1.1", "any 0.0.0.0", "file 1.2.3.4.5", "time 12:34:56", "FirmwareVersion 10.20.30.40",
	}
	for _, s := range keep {
		if got := rd(s); got != s {
			t.Errorf("changed %q -> %q", s, got)
		}
	}
	if got := rd("DNS 192.168.1.1 gw 203.0.113.9"); !strings.Contains(got, "IP-PRIV-1") || !strings.Contains(got, "IP-PUB-1") {
		t.Errorf("addresses not redacted: %s", got)
	}
}

func TestRedactMACEmailSID(t *testing.T) {
	got := rd("mac 1C-CE-51-5D-FA-5A and 1c:ce:51:5d:fa:5a zero 00-00-00-00-00-00 mail Jane.Doe@contoso.com sid S-1-5-21-111-222-333-500 well S-1-5-18")
	if strings.Contains(got, "1C-CE") || strings.Contains(strings.ToLower(got), "1c:ce") || strings.Contains(got, "Jane") || strings.Contains(got, "111-222") {
		t.Errorf("leak: %s", got)
	}
	if strings.Count(got, "MAC-1") != 2 || !strings.Contains(got, "00-00-00-00-00-00") || !strings.Contains(got, "-500") || !strings.Contains(got, "S-1-5-18") {
		t.Errorf("unexpected: %s", got)
	}
}

func TestRedactSerials(t *testing.T) {
	list := "SerialNumber      : ABC123XYZ\nSerialNumber      : System Serial Number\n"
	got := rd(list)
	if strings.Contains(got, "ABC123XYZ") || !strings.Contains(got, "System Serial Number") {
		t.Errorf("list form: %s", got)
	}
	tbl := "Bank DeviceLocator Capacity SerialNumber\n---- ------------- -------- ------------\nA    DIMM1         16       00AB12CD\nB    DIMM2         16       Unknown\n\nnext 00AB12CD stays? no\n"
	got = rd(tbl)
	if strings.Contains(strings.SplitN(got, "\n\n", 2)[0], "00AB12CD") || !strings.Contains(got, "Unknown") {
		t.Errorf("table form: %s", got)
	}
	if !strings.Contains(got, "SERIAL-1") {
		t.Errorf("no placeholder: %s", got)
	}
}

func TestRedactProfilesAndOneDrive(t *testing.T) {
	got := rd(`C:\Users\Bob\Documents C:\Users\Public\x C:\Users\Default\y D:\OneDrive - Fabrikam Pty Ltd\Mail.ost`)
	if strings.Contains(got, "Bob") || strings.Contains(got, "Fabrikam") || !strings.Contains(got, `\Users\Public\`) || !strings.Contains(got, `\Users\Default\`) {
		t.Errorf("got %s", got)
	}
}

func TestCommonUserNameNotFreeText(t *testing.T) {
	r := newRedactor(identity{Host: "PC-LAB-01", User: "User", ProfileDir: "User"})
	got := r.Redact(`User Account Control is on. C:\Users\User\x.dmp PC-LAB-01\User ok`)
	if !strings.Contains(got, "User Account Control") || strings.Contains(got, `\Users\User\`) || strings.Contains(got, `HOST-1\User`) {
		t.Errorf("got %s", got)
	}
}

func TestRedactFiles(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "HealthReport_DESKTOP-5OCD5RH_20261027-1_part1of2.md")
	p2 := filepath.Join(dir, "HealthReport_DESKTOP-5OCD5RH_20261027-1_part2of2.md")
	os.WriteFile(p1, []byte("# PART 1 OF 2 - DESKTOP-5OCD5RH\nip 10.9.8.7\n"), 0o600)
	os.WriteFile(p2, []byte("part two 10.9.8.7 andrewlike andrew\n"), 0o600)
	np, mp, sum, err := redactFiles([]string{p1, p2}, testID, "20261027-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(np) != 2 || strings.Contains(np[0], "DESKTOP") {
		t.Fatalf("not renamed: %v", np)
	}
	for _, p := range []string{p1, p2} {
		if _, e := os.Stat(p); e == nil {
			t.Errorf("original %s still exists", p)
		}
	}
	a, _ := os.ReadFile(np[0])
	b, _ := os.ReadFile(np[1])
	if !strings.HasPrefix(string(a), "> **Redacted report.**") || strings.HasPrefix(string(b), ">") {
		t.Errorf("note placement wrong:\n%s\n---\n%s", a, b)
	}
	if !strings.Contains(string(a), "IP-PRIV-1") || !strings.Contains(string(b), "IP-PRIV-1") {
		t.Errorf("placeholder not shared across parts")
	}
	m, _ := os.ReadFile(mp)
	if !strings.Contains(string(m), "10.9.8.7") || !strings.Contains(string(m), "DESKTOP-5OCD5RH") || !strings.Contains(filepath.Base(mp), "DO-NOT-UPLOAD") {
		t.Errorf("map wrong: %s %s", mp, m)
	}
	if !strings.Contains(sum, "private IP") {
		t.Errorf("summary: %s", sum)
	}
}

// Optional: run against real report files without committing them.
//
//	REDACT_SAMPLE_DIR=/path go test -run TestRedactSamples -v
func TestRedactSamples(t *testing.T) {
	dir := os.Getenv("REDACT_SAMPLE_DIR")
	if dir == "" {
		t.Skip("REDACT_SAMPLE_DIR not set")
	}
	id := identity{Host: os.Getenv("REDACT_HOST"), User: os.Getenv("REDACT_USER"), ProfileDir: os.Getenv("REDACT_USER")}
	files, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	r := newRedactor(id)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		out := r.Redact(string(b))
		if id.Host != "" && strings.Contains(strings.ToLower(out), strings.ToLower(id.Host)) {
			t.Errorf("%s: host survived", filepath.Base(f))
		}
		if os.Getenv("REDACT_DUMP") != "" {
			os.WriteFile(filepath.Join(os.Getenv("REDACT_DUMP"), filepath.Base(f)), []byte(out), 0o600)
		}
	}
	if d := os.Getenv("REDACT_DUMP"); d != "" {
		os.WriteFile(filepath.Join(d, "MAP.txt"), []byte(r.MapText("test")), 0o600)
	}
	t.Log(r.Summary())
}
