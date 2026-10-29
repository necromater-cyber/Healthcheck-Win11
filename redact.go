package main

// Best-effort redaction of identifying details from finished report files.
//
// It runs in the launcher after the collector has written its Markdown, so the same code covers both
// collectors and the PowerShell scripts stay unchanged. Placeholders are stable within a run
// (the same value always becomes the same placeholder), and the mapping is written to a separate local
// file so the person who ran the check can still tell which machine, user or address a finding is about.
//
// This is a safety net, not a guarantee. It cannot know every name in free text (other users' names,
// project names, file names). Review a redacted report before sharing it.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// identity holds the values that identify this machine and its user. Tests supply their own.
type identity struct {
	Host, User, Domain, DNSDomain, ProfileDir string
}

func identityFromEnv() identity {
	host := os.Getenv("COMPUTERNAME")
	if host == "" {
		host, _ = os.Hostname()
	}
	dom := os.Getenv("USERDOMAIN")
	if strings.EqualFold(dom, host) || strings.EqualFold(dom, "WORKGROUP") {
		dom = ""
	}
	return identity{
		Host:       host,
		User:       os.Getenv("USERNAME"),
		Domain:     dom,
		DNSDomain:  os.Getenv("USERDNSDOMAIN"),
		ProfileDir: filepath.Base(os.Getenv("USERPROFILE")),
	}
}

// commonNames are never replaced as free text because they would corrupt ordinary sentences
// ("User Account Control", "Administrators"). They are still replaced where they are clearly a
// profile folder or a DOMAIN\name pair.
var commonNames = map[string]bool{
	"user": true, "users": true, "admin": true, "administrator": true, "guest": true, "owner": true,
	"public": true, "default": true, "system": true, "test": true, "local": true, "service": true,
}

// keepProfiles are well-known folders under C:\Users that carry no personal information.
var keepProfiles = map[string]bool{
	"public": true, "default": true, "default user": true, "all users": true, "administrator": true,
	"defaultuser0": true, "desktop.ini": true,
}

// wellKnownDNS are public resolvers that are not identifying and that the tool itself tests.
var wellKnownDNS = map[string]bool{
	"0.0.0.0": true, "8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true, "9.9.9.9": true,
	"149.112.112.112": true, "208.67.222.222": true, "208.67.220.220": true,
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true, "2606:4700:4700::1111": true,
	"2606:4700:4700::1001": true, "2620:fe::fe": true, "2620:fe::9": true,
}

// placeholderSerials are values firmware leaves in when a serial number was never set. They are
// diagnostically useful and identify nothing, so they are kept.
var placeholderSerials = []string{
	"to be filled", "default string", "system serial", "not specified", "none", "n/a", "unknown",
	"serial number", "o.e.m", "0", "123456789", "not available", "not applicable",
}

type redactor struct {
	id     identity
	maps   map[string]map[string]string // category -> original (lower-cased) -> placeholder
	order  map[string][]string          // category -> originals in first-seen order, for the map file
	counts map[string]int
	host   *regexp.Regexp
	user   *regexp.Regexp
	dom    *regexp.Regexp
	dns    *regexp.Regexp
	prof   *regexp.Regexp
}

var (
	reEmail       = regexp.MustCompile(`[A-Za-z0-9._%+'\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
	reSID         = regexp.MustCompile(`S-1-5-21-(\d+)-(\d+)-(\d+)(-\d+)?`)
	reMAC         = regexp.MustCompile(`[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}`)
	reIPv4        = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	reIPv6        = regexp.MustCompile(`(?i)\b(?:fe80|fd[0-9a-f]{2}|[23][0-9a-f]{3})(?::[0-9a-f]{0,4}){2,7}(?:%\d+)?`)
	reProfile     = regexp.MustCompile(`(?i)(\\Users\\)([^\\/\s"'<>|:*?]+)`)
	reOneDrive    = regexp.MustCompile(`(?i)(OneDrive - )([^\\/\r\n"<>|]+)`)
	reSerialLine  = regexp.MustCompile(`(?im)^(\s*[A-Za-z ]*?(?:serial ?number|serialnumber|uuid|machine ?guid|asset ?tag|product ?id)\s*[:=]\s*)(\S.*?)[ \t]*$`)
	reSerialHdr   = regexp.MustCompile(`(?i)\b(?:BIOS)?SerialNumber\b`)
	reTableCell   = regexp.MustCompile(`^\S+(?: \S+)*`)
	reVersionWord = regexp.MustCompile(`(?i)version|build|driver|firmware|bios date`)
	// A row that carries a date is a software, driver or update listing: dotted numbers in it are versions.
	reDateLike = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{4}\b|\b20\d{6}\b`)
	// Public addresses are only redacted on lines that are about the network.
	reNetLine = regexp.MustCompile(`(?i)address|dns|gateway|resolved|server|endpoint|remote|route|hop|ping|nameserver|proxy|\bip\b|host|connect|tcp|udp|listen|established|->|=>`)
)

func newRedactor(id identity) *redactor {
	r := &redactor{
		id:     id,
		maps:   map[string]map[string]string{},
		order:  map[string][]string{},
		counts: map[string]int{},
	}
	lit := func(s string, minLen int) *regexp.Regexp {
		if len(s) < minLen {
			return nil
		}
		q := regexp.QuoteMeta(s)
		if len(s) < 5 { // short names must not match inside other words
			return regexp.MustCompile(`(?i)\b` + q + `\b`)
		}
		return regexp.MustCompile(`(?i)` + q)
	}
	// Seed the machine and the current user so they are always HOST-1 and USER-1.
	if id.Host != "" {
		r.alloc("HOST", id.Host)
		r.host = lit(id.Host, 3)
	}
	if id.User != "" {
		r.alloc("USER", id.User)
		if !commonNames[strings.ToLower(id.User)] {
			r.user = lit(id.User, 4)
		}
	}
	if id.ProfileDir != "" && !strings.EqualFold(id.ProfileDir, id.User) && !keepProfiles[strings.ToLower(id.ProfileDir)] {
		r.alloc("USER", id.ProfileDir)
		r.prof = regexp.MustCompile(`(?i)(\\Users\\)` + regexp.QuoteMeta(id.ProfileDir))
	}
	if id.Domain != "" {
		r.alloc("DOMAIN", id.Domain)
		r.dom = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(id.Domain) + `\b`)
	}
	if id.DNSDomain != "" {
		r.alloc("DNSDOMAIN", id.DNSDomain)
		r.dns = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(id.DNSDomain))
	}
	return r
}

// alloc returns the placeholder for a value, creating it on first use.
func (r *redactor) alloc(cat, val string) string {
	key := strings.ToLower(val)
	m := r.maps[cat]
	if m == nil {
		m = map[string]string{}
		r.maps[cat] = m
	}
	if p, ok := m[key]; ok {
		return p
	}
	r.counts[cat]++
	p := fmt.Sprintf("%s-%d", cat, r.counts[cat])
	m[key] = p
	r.order[cat] = append(r.order[cat], val)
	return p
}

func isPlaceholderSerial(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	if l == "" || strings.Trim(l, "0.-_ ") == "" {
		return true
	}
	for _, p := range placeholderSerials {
		if p == "0" || p == "none" || p == "n/a" || p == "unknown" {
			if l == p {
				return true
			}
			continue
		}
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// Redact applies every rule to one file's text. Call it for each file of a run with the same redactor.
func (r *redactor) Redact(s string) string {
	// 1. Addresses first, so a user name inside an e-mail address is not split up.
	s = reEmail.ReplaceAllStringFunc(s, func(m string) string { return r.alloc("EMAIL", m) })

	// 2. Account domain SIDs (keep the trailing RID: 500 = built-in Administrator is informative).
	s = reSID.ReplaceAllStringFunc(s, func(m string) string {
		g := reSID.FindStringSubmatch(m)
		return "S-1-5-21-" + r.alloc("SID", g[1]+"-"+g[2]+"-"+g[3]) + g[4]
	})

	// 3. Network identifiers.
	s = reMAC.ReplaceAllStringFunc(s, func(m string) string {
		u := strings.ToUpper(strings.NewReplacer(":", "-").Replace(m))
		if u == "00-00-00-00-00-00" || u == "FF-FF-FF-FF-FF-FF" {
			return m
		}
		return r.alloc("MAC", u)
	})
	s = r.redactIPv4(s)
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		if wellKnownDNS[strings.ToLower(m)] {
			return m
		}
		return r.alloc("IPV6", strings.ToLower(m))
	})

	// 4. Serial numbers and similar hardware identifiers.
	s = reSerialLine.ReplaceAllStringFunc(s, func(m string) string {
		g := reSerialLine.FindStringSubmatch(m)
		if isPlaceholderSerial(g[2]) {
			return m
		}
		return g[1] + r.alloc("SERIAL", g[2])
	})
	s = r.redactSerialColumns(s)

	// 5. Names: profile folders, then DOMAIN\name pairs, then the known identity values.
	if r.prof != nil {
		s = r.prof.ReplaceAllString(s, "${1}"+r.alloc("USER", r.id.ProfileDir))
	}
	s = reProfile.ReplaceAllStringFunc(s, func(m string) string {
		g := reProfile.FindStringSubmatch(m)
		name := g[2]
		if keepProfiles[strings.ToLower(name)] || strings.HasPrefix(name, "USER-") {
			return m
		}
		return g[1] + r.alloc("USER", name)
	})
	s = reOneDrive.ReplaceAllStringFunc(s, func(m string) string {
		g := reOneDrive.FindStringSubmatch(m)
		return g[1] + r.alloc("ORG", strings.TrimSpace(g[2]))
	})
	if r.id.User != "" {
		pair := regexp.MustCompile(`(?i)(\\)` + regexp.QuoteMeta(r.id.User) + `\b`)
		s = pair.ReplaceAllString(s, "${1}"+r.alloc("USER", r.id.User))
	}
	if r.dns != nil {
		s = r.dns.ReplaceAllString(s, r.alloc("DNSDOMAIN", r.id.DNSDomain))
	}
	if r.dom != nil {
		s = r.dom.ReplaceAllString(s, r.alloc("DOMAIN", r.id.Domain))
	}
	if r.host != nil {
		s = r.host.ReplaceAllString(s, r.alloc("HOST", r.id.Host))
	}
	if r.user != nil {
		s = r.user.ReplaceAllString(s, r.alloc("USER", r.id.User))
	}
	return s
}

// redactIPv4 replaces addresses but leaves things that are not host-specific or are not addresses:
// masks, loopback, 0.0.0.0, multicast, the public resolvers the tool pings, and dotted version
// numbers (a line that talks about versions, builds, drivers or firmware is left alone).
func (r *redactor) redactIPv4(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if !reIPv4.MatchString(ln) {
			continue
		}
		skipLine := reVersionWord.MatchString(ln) || reDateLike.MatchString(ln)
		netLine := reNetLine.MatchString(ln)
		lines[i] = replaceWithOffset(reIPv4, ln, func(m string, start int) string {
			if skipLine {
				return m
			}
			// not part of a longer dotted/number run (1.2.3.4.5, 10.0.19041.1234)
			if start > 0 && (ln[start-1] == '.' || isDigit(ln[start-1])) {
				return m
			}
			if end := start + len(m); end < len(ln) && (isDigit(ln[end]) || (ln[end] == '.' && end+1 < len(ln) && isDigit(ln[end+1]))) {
				return m
			}
			oct := strings.Split(m, ".")
			var o [4]int
			for k, p := range oct {
				if len(p) > 1 && p[0] == '0' {
					return m
				}
				n := 0
				for _, c := range p {
					n = n*10 + int(c-'0')
				}
				if n > 255 {
					return m
				}
				o[k] = n
			}
			switch {
			case wellKnownDNS[m]:
				return m
			case o[0] == 127, o[0] == 255, o[0] >= 224 && o[0] <= 239, o[0] == 0:
				return m
			}
			priv := o[0] == 10 || (o[0] == 172 && o[1] >= 16 && o[1] <= 31) || (o[0] == 192 && o[1] == 168) || (o[0] == 169 && o[1] == 254)
			if priv {
				return r.alloc("IP-PRIV", m)
			}
			if !netLine {
				return m
			}
			return r.alloc("IP-PUB", m)
		})
	}
	return strings.Join(lines, "\n")
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// replaceWithOffset is ReplaceAllStringFunc with the match offset, needed to look at the characters
// around a match.
func replaceWithOffset(re *regexp.Regexp, s string, fn func(m string, start int) string) string {
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringIndex(s, -1) {
		b.WriteString(s[last:loc[0]])
		b.WriteString(fn(s[loc[0]:loc[1]], loc[0]))
		last = loc[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactSerialColumns handles Format-Table output, where the serial number sits in a column under a
// "SerialNumber" header instead of after a colon.
func (r *redactor) redactSerialColumns(s string) string {
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		loc := reSerialHdr.FindStringIndex(lines[i])
		if loc == nil {
			continue
		}
		// A table header is followed by a dashed underline; require it so prose is not touched.
		if i+1 >= len(lines) || !strings.Contains(lines[i+1], "---") {
			continue
		}
		col := loc[0]
		for j := i + 2; j < len(lines); j++ {
			cr := ""
			row := lines[j]
			if strings.HasSuffix(row, "\r") {
				cr, row = "\r", strings.TrimSuffix(row, "\r")
			}
			if strings.TrimSpace(row) == "" {
				break
			}
			if col >= len(row) {
				continue
			}
			cell := reTableCell.FindString(row[col:])
			if cell == "" || isPlaceholderSerial(cell) {
				continue
			}
			lines[j] = row[:col] + r.alloc("SERIAL", cell) + row[col+len(cell):] + cr
		}
	}
	return strings.Join(lines, "\n")
}

// Summary returns a one-line description of what was replaced, e.g. "1 host, 1 user, 9 IP addresses".
func (r *redactor) Summary() string {
	names := []struct{ cat, one, many string }{
		{"HOST", "host name", "host names"}, {"USER", "user name", "user names"},
		{"DOMAIN", "domain", "domains"}, {"DNSDOMAIN", "DNS domain", "DNS domains"},
		{"EMAIL", "e-mail address", "e-mail addresses"}, {"SID", "domain SID", "domain SIDs"},
		{"IP-PRIV", "private IP", "private IPs"}, {"IP-PUB", "public IP", "public IPs"},
		{"IPV6", "IPv6 address", "IPv6 addresses"}, {"MAC", "MAC address", "MAC addresses"},
		{"SERIAL", "serial number", "serial numbers"}, {"ORG", "organisation name", "organisation names"},
	}
	var parts []string
	for _, n := range names {
		c := len(r.order[n.cat])
		if c == 0 {
			continue
		}
		w := n.many
		if c == 1 {
			w = n.one
		}
		parts = append(parts, fmt.Sprintf("%d %s", c, w))
	}
	if len(parts) == 0 {
		return "nothing matched"
	}
	return strings.Join(parts, ", ")
}

// MapText is the contents of the local mapping file.
func (r *redactor) MapText(stamp string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HealthCheck redaction map (%s)\n", stamp)
	b.WriteString("KEEP THIS FILE PRIVATE. Do NOT upload or share it: it lists the real values behind the placeholders.\n\n")
	cats := make([]string, 0, len(r.order))
	for c := range r.order {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		for i, v := range r.order[c] {
			fmt.Fprintf(&b, "%s-%d\t%s\n", c, i+1, v)
		}
	}
	return b.String()
}

// redactNote is prepended to the first file of a report so the AI does not treat placeholders as
// real names or as findings.
const redactNote = "> **Redacted report.** Identifying details were replaced with placeholders such as HOST-1, USER-1, " +
	"IP-PRIV-1, IP-PUB-1, MAC-1, EMAIL-1 and SERIAL-1. Each placeholder always stands for the same real value " +
	"within this run. Treat them as ordinary names; do not report them as anomalies or ask for the real values.\n\n"

var rePartN = regexp.MustCompile(`_part(\d+)of\d+\.md$`)

// redactFiles rewrites each report with identifying details replaced, renames files whose names contain
// the host name, and writes the mapping file next to the first report. It returns the new paths, the
// mapping file's path and a short description of what was replaced. Originals are removed only after
// the redacted copy has been written.
func redactFiles(paths []string, id identity, stamp string) (newPaths []string, mapPath, summary string, err error) {
	if len(paths) == 0 {
		return nil, "", "", nil
	}
	r := newRedactor(id)
	for _, p := range paths {
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return paths, "", "", rerr
		}
		bom := strings.HasPrefix(string(b), "\xEF\xBB\xBF")
		text := strings.TrimPrefix(string(b), "\xEF\xBB\xBF")
		out := r.Redact(text)
		if m := rePartN.FindStringSubmatch(p); m == nil || m[1] == "1" {
			out = redactNote + out
		}
		np := filepath.Join(filepath.Dir(p), r.Redact(filepath.Base(p)))
		data := []byte(out)
		if bom {
			data = append([]byte{0xEF, 0xBB, 0xBF}, data...)
		}
		if werr := os.WriteFile(np, data, 0o600); werr != nil {
			return paths, "", "", werr
		}
		if np != p {
			_ = os.Remove(p)
		}
		newPaths = append(newPaths, np)
	}
	mapPath = filepath.Join(filepath.Dir(newPaths[0]), "DO-NOT-UPLOAD_redaction-map_"+stamp+".txt")
	if werr := os.WriteFile(mapPath, []byte(r.MapText(stamp)), 0o600); werr != nil {
		return newPaths, "", r.Summary(), werr
	}
	return newPaths, mapPath, r.Summary(), nil
}
