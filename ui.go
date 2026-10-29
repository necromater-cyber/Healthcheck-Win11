package main

// Console presentation: colour, box drawing, a live progress bar and the result summary.
// Standard library only. Everything degrades to plain text when output is redirected,
// NO_COLOR is set, TERM=dumb, or HEALTHCHECK_PLAIN is set, so logs and CI stay clean.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type theme struct{ color bool }

var ui theme

// initUI decides once, at start-up, whether rich output is safe.
func initUI() {
	if !stdoutIsTerminal() {
		return
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("HEALTHCHECK_PLAIN") != "" || os.Getenv("TERM") == "dumb" {
		return
	}
	ui.color = enableVT()
}

func paint(code, s string) string {
	if !ui.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string   { return paint("1", s) }
func dim(s string) string    { return paint("90", s) }
func cyan(s string) string   { return paint("36", s) }
func green(s string) string  { return paint("32", s) }
func yellow(s string) string { return paint("33", s) }
func red(s string) string    { return paint("31", s) }

// glyph returns the fancy form when colour/UTF-8 is active, otherwise a plain ASCII fallback.
func glyph(fancy, plain string) string {
	if ui.color {
		return fancy
	}
	return plain
}

func fmtElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
}

// ---------------------------------------------------------------------------
// Boxed header
// ---------------------------------------------------------------------------

const boxInner = 60

type boxLine struct{ plain, styled string }

func padTo(l boxLine, width int) string {
	n := utf8.RuneCountInString(l.plain)
	if n >= width {
		return l.styled
	}
	return l.styled + strings.Repeat(" ", width-n)
}

func drawBox(lines []boxLine) {
	if !ui.color {
		bar := strings.Repeat("=", boxInner+2)
		fmt.Println(bar)
		for _, l := range lines {
			fmt.Println(" " + l.plain)
		}
		fmt.Println(bar)
		return
	}
	h := strings.Repeat("─", boxInner+2)
	fmt.Println(cyan("╭" + h + "╮"))
	for _, l := range lines {
		fmt.Println(cyan("│") + " " + padTo(l, boxInner) + " " + cyan("│"))
	}
	fmt.Println(cyan("╰" + h + "╯"))
}

func banner() {
	admin := isAdmin()
	who := "standard user"
	whoStyled := yellow(who)
	if admin {
		who, whoStyled = "Administrator", green("Administrator")
	}
	left := fmt.Sprintf("HealthCheck %s", version)
	right := fmt.Sprintf("built %s", buildDate)
	gap := boxInner - utf8.RuneCountInString(left) - utf8.RuneCountInString(right)
	if gap < 2 {
		gap = 2
	}
	title := boxLine{
		plain:  left + strings.Repeat(" ", gap) + right,
		styled: bold(left) + strings.Repeat(" ", gap) + dim(right),
	}
	col := fmt.Sprintf("Windows collector %s  %s  Outlook collector %s",
		collectorVersion(windowsScript), glyph("·", "|"), collectorVersion(outlookScript))
	run := "Running as " + who
	drawBox([]boxLine{
		title,
		{plain: col, styled: dim(col)},
		{plain: run, styled: dim("Running as ") + whoStyled},
	})
}

// ---------------------------------------------------------------------------
// Live progress
// ---------------------------------------------------------------------------

var sectionRE = regexp.MustCompile(`^\s*->\s+(.+?)\s*$`)

// countSections estimates how many "-> section" lines a script will print.
func countSections(script []byte) int {
	n := len(regexp.MustCompile(`(?m)^\s*Add-Section\b`).FindAll(script, -1))
	if bytes.Contains(script, []byte("Building triage digest")) {
		n++
	}
	return n
}

type progress struct {
	mu    sync.Mutex
	live  bool
	title string
	n     int
	total int
	start time.Time
	frame int
	shown bool
	stop  chan struct{}
	done  chan struct{}
}

func newProgress(total int) *progress {
	p := &progress{live: ui.color, total: total, start: time.Now(), stop: make(chan struct{}), done: make(chan struct{})}
	if p.live {
		go p.tick()
	} else {
		close(p.done)
	}
	return p
}

func (p *progress) tick() {
	defer close(p.done)
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.mu.Lock()
			p.frame++
			p.draw()
			p.mu.Unlock()
		}
	}
}

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (p *progress) draw() { // caller holds the lock
	if !p.live {
		return
	}
	total := p.total
	if p.n > total {
		total = p.n
	}
	const width = 24
	fill := 0
	if total > 0 {
		fill = p.n * width / total
	}
	bar := green(strings.Repeat("█", fill)) + dim(strings.Repeat("░", width-fill))
	title := p.title
	if utf8.RuneCountInString(title) > 44 {
		title = string([]rune(title)[:43]) + "…"
	}
	if title == "" {
		title = "starting…"
	}
	line := fmt.Sprintf("  %s %s %s  %s  %s",
		cyan(spinner[p.frame%len(spinner)]), bar,
		bold(fmt.Sprintf("%d/%d", p.n, total)), title, dim(fmtElapsed(time.Since(p.start))))
	fmt.Print("\r\x1b[2K" + line)
	p.shown = true
}

func (p *progress) clear() { // caller holds the lock
	if p.live && p.shown {
		fmt.Print("\r\x1b[2K")
		p.shown = false
	}
}

func (p *progress) section(title string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	p.title = title
	p.draw()
}

// line prints a message above the progress bar.
func (p *progress) line(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clear()
	fmt.Println(s)
	p.draw()
}

func (p *progress) finish() {
	if p.live {
		close(p.stop)
		<-p.done
	}
	p.mu.Lock()
	p.clear()
	p.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Child-output filter
// ---------------------------------------------------------------------------

// uiWriter receives the PowerShell output. It always records the raw text (so report paths can be
// found afterwards) and, in rich mode, turns the "-> Section" lines into a progress bar and hides
// the script's own banner/footer chatter that the summary panel replaces.
type uiWriter struct {
	mu   sync.Mutex
	capt *pathCapture
	prog *progress
	buf  []byte
}

var noiseRE = regexp.MustCompile(`^\s*(Windows 11 Health Collector|Outlook Health & Performance Collector|Window: last|Collecting\.\.\.|Done in |Verbosity: |Report: |Upload ALL|PRIVACY:|installed software\. Review|\(?[A-Za-z]:\\.*\.md)`)

func (w *uiWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.capt.Write(b)
	if !ui.color {
		return os.Stdout.Write(b)
	}
	w.buf = append(w.buf, b...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.handle(strings.TrimRight(string(w.buf[:i]), "\r"))
		w.buf = w.buf[i+1:]
	}
	return len(b), nil
}

func (w *uiWriter) handle(s string) {
	if m := sectionRE.FindStringSubmatch(s); m != nil {
		w.prog.section(m[1])
		return
	}
	if strings.TrimSpace(s) == "" || noiseRE.MatchString(s) {
		return
	}
	switch {
	case strings.HasPrefix(strings.TrimSpace(s), "NOTE") || strings.Contains(s, "WARNING"):
		w.prog.line("  " + yellow(strings.TrimSpace(s)))
	case strings.HasPrefix(strings.TrimSpace(s), "-Verbosity"):
		w.prog.line("  " + yellow(strings.TrimSpace(s)))
	default:
		w.prog.line("  " + s)
	}
}

func (w *uiWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 && ui.color {
		w.handle(strings.TrimRight(string(w.buf), "\r\n"))
		w.buf = nil
	}
}

var _ io.Writer = (*uiWriter)(nil)

// ---------------------------------------------------------------------------
// Result summary
// ---------------------------------------------------------------------------

var flagTotalsRE = regexp.MustCompile(`Flag totals:\s*([^\r\n]+)`)
var flagPairRE = regexp.MustCompile(`([A-Z][A-Z \-]*?)=(\d+)`)

// readFlagTotals pulls the "Flag totals" line out of the first report file.
func readFlagTotals(path string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	m := flagTotalsRE.FindSubmatch(b)
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for _, p := range flagPairRE.FindAllStringSubmatch(string(m[1]), -1) {
		out[strings.TrimSpace(p[1])] = p[2]
	}
	return out
}

func renderFlags(t map[string]string) string {
	type fl struct {
		key, label string
		style      func(string) string
	}
	order := []fl{
		{"ACTION - CRITICAL", "CRITICAL", red},
		{"ACTION", "ACTION", red},
		{"WATCH", "WATCH", yellow},
		{"OK", "OK", green},
		{"INFO", "INFO", dim},
	}
	var parts []string
	for _, f := range order {
		if v, ok := t[f.key]; ok && v != "0" {
			parts = append(parts, f.style(bold(v)+" "+f.label))
		}
	}
	return strings.Join(parts, "  "+glyph("·", "|")+"  ")
}

func fileSizeKB(p string) string {
	if st, err := os.Stat(p); err == nil {
		return fmt.Sprintf("%.1f KB", float64(st.Size())/1024)
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// printSummary writes the closing panel. It returns the process exit code.
func printSummary(label string, code int, paths []string, err error, elapsed time.Duration) int {
	fmt.Println()
	ok, bad := glyph("✔", "[ok]"), glyph("✖", "[x]")
	if err != nil {
		fmt.Printf("%s %s\n  %v\n", red(bad), bold(label+": could not run"), err)
		return 1
	}
	if code != 0 {
		fmt.Printf("%s %s %s\n", red(bad), bold(label+": PowerShell exited with code"), red(fmt.Sprint(code)))
		fmt.Println(dim("  If the message above mentions execution policy, AppLocker or Constrained Language Mode,"))
		fmt.Println(dim("  your organisation restricts script execution - ask IT to allow-list HealthCheck.exe."))
		return code
	}
	if len(paths) == 0 {
		fmt.Printf("%s %s %s\n", yellow(glyph("!", "[!]")), bold(label+": finished"), dim("(no report path was detected in the output)"))
		return 0
	}
	fmt.Printf("%s %s %s\n", green(ok), bold(label+" complete"), dim("in "+fmtElapsed(elapsed)))
	fmt.Println()
	fmt.Println("  " + bold("Report file(s)"))
	for _, p := range paths {
		fmt.Printf("    %s  %s\n", cyan(baseName(p)), dim(fileSizeKB(p)))
	}
	fmt.Println(dim("    in " + dirOf(paths[0])))
	if t := readFlagTotals(paths[0]); len(t) > 0 {
		fmt.Println()
		fmt.Println("  " + bold("Triage") + "  " + renderFlags(t))
	}
	fmt.Println()
	if len(paths) > 1 {
		fmt.Printf("  %s Upload all %d parts to the AI assistant, in order, before asking for analysis.\n", cyan(glyph("›", ">")), len(paths))
	} else {
		fmt.Printf("  %s Upload this file to the AI assistant and ask it to follow the instructions at the top.\n", cyan(glyph("›", ">")))
	}
	fmt.Println(dim("  Privacy: reports contain hostname, usernames, serial numbers, IP addresses and installed software."))
	return 0
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return "."
}
