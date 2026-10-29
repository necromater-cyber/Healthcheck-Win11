// HealthCheck - single-file launcher for the Windows 11 and Outlook health collectors.
//
// The two PowerShell collectors are embedded in this binary. At run time they are written
// to a private temp folder, executed with Windows PowerShell 5.1, and deleted afterwards.
// Standard library only - no third-party dependencies.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

//go:embed scripts/Get-Windows11HealthReport.ps1
var windowsScript []byte

//go:embed scripts/Get-OutlookHealthReport.ps1
var outlookScript []byte

// Overridden at build time with -ldflags "-X main.version=... -X main.buildDate=...".
var (
	version   = "1.0.0"
	buildDate = "dev"
)

const (
	winScriptName = "Get-Windows11HealthReport.ps1"
	olScriptName  = "Get-OutlookHealthReport.ps1"
)

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type winOpts struct {
	days, maxPartKB, maxUptime int
	out, verbosity             string
	split, integrity, battery  bool
	copilot, redact            bool
	yesElevate, noElevate      bool
	raw                        []string
}

type olOpts struct {
	days, warn, action int
	out                string
	deep               bool
	deelevated, redact bool
	endpoints          stringList
	raw                []string
}

type allOpts struct {
	days       int
	out        string
	copilot    bool
	redact     bool
	noElevate  bool
	yesElevate bool
}

func splitRaw(args []string) (own, raw []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func newFS(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func winFlags(fs *flag.FlagSet, o *winOpts) {
	fs.IntVar(&o.days, "days", 0, "event log lookback in days, 1-365 (script default 7)")
	fs.StringVar(&o.out, "out", "", "output folder (default: Desktop)")
	fs.StringVar(&o.verbosity, "verbosity", "", "compact | standard | full (script default standard)")
	fs.BoolVar(&o.split, "split", false, "split the report into several smaller files")
	fs.IntVar(&o.maxPartKB, "max-part-kb", 0, "max size of each split part in KB, 20-5000")
	fs.IntVar(&o.maxUptime, "max-uptime-days", 0, "restart-cadence policy in days, 1-90 (script default 7)")
	fs.BoolVar(&o.integrity, "integrity", false, "also run DISM / SFC read-only integrity checks (slow)")
	fs.BoolVar(&o.battery, "battery", false, "also produce a battery report (laptops)")
	fs.BoolVar(&o.copilot, "copilot", false, "preset for chat-assistant upload: compact + split into at most 3 parts (Copilot upload limit), 3-day window")
	fs.BoolVar(&o.redact, "redact", false, "replace host/user names, IPs, MACs, e-mails and serials in the finished report with placeholders")
	fs.BoolVar(&o.yesElevate, "elevate", false, "relaunch as Administrator without asking")
	fs.BoolVar(&o.noElevate, "no-elevate", false, "never offer to relaunch as Administrator")
}

func olFlags(fs *flag.FlagSet, o *olOpts) {
	fs.IntVar(&o.days, "days", 0, "event log lookback in days, 1-90 (script default 14)")
	fs.StringVar(&o.out, "out", "", "output folder (default: Desktop)")
	fs.BoolVar(&o.redact, "redact", false, "replace host/user names, IPs, MACs, e-mails and serials in the finished report with placeholders")
	fs.BoolVar(&o.deelevated, "deelevated", false, "internal: set when relaunched without administrator rights")
	fs.BoolVar(&o.deep, "deep-folder-scan", false, "scan all stores and deeper subfolders (slower)")
	fs.Var(&o.endpoints, "endpoint", "extra host to test, e.g. on-prem Exchange/Autodiscover (repeatable)")
	fs.IntVar(&o.warn, "folder-warn", 0, "folder item-count warning threshold, 1000-500000")
	fs.IntVar(&o.action, "folder-action", 0, "folder item-count action threshold, 1000-1000000")
}

func inRange(name string, v, lo, hi int) error {
	if v != 0 && (v < lo || v > hi) {
		return fmt.Errorf("--%s must be between %d and %d (got %d)", name, lo, hi, v)
	}
	return nil
}

func normVerbosity(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return "", nil
	case "compact":
		return "Compact", nil
	case "standard":
		return "Standard", nil
	case "full":
		return "Full", nil
	}
	return "", fmt.Errorf("--verbosity must be compact, standard or full (got %q)", v)
}

func parseWindows(args []string) (winOpts, error) {
	var o winOpts
	own, raw := splitRaw(args)
	o.raw = raw
	fs := newFS("windows")
	winFlags(fs, &o)
	if err := fs.Parse(own); err != nil {
		return o, err
	}
	for _, c := range []error{
		inRange("days", o.days, 1, 365),
		inRange("max-part-kb", o.maxPartKB, 20, 5000),
		inRange("max-uptime-days", o.maxUptime, 1, 90),
	} {
		if c != nil {
			return o, c
		}
	}
	v, err := normVerbosity(o.verbosity)
	if err != nil {
		return o, err
	}
	o.verbosity = v
	return o, nil
}

func parseOutlook(args []string) (olOpts, error) {
	var o olOpts
	own, raw := splitRaw(args)
	o.raw = raw
	fs := newFS("outlook")
	olFlags(fs, &o)
	if err := fs.Parse(own); err != nil {
		return o, err
	}
	for _, c := range []error{
		inRange("days", o.days, 1, 90),
		inRange("folder-warn", o.warn, 1000, 500000),
		inRange("folder-action", o.action, 1000, 1000000),
	} {
		if c != nil {
			return o, c
		}
	}
	return o, nil
}

func parseAll(args []string) (allOpts, error) {
	var o allOpts
	fs := newFS("all")
	fs.IntVar(&o.days, "days", 0, "lookback in days, applied to both checks (1-90)")
	fs.StringVar(&o.out, "out", "", "output folder (default: Desktop)")
	fs.BoolVar(&o.copilot, "copilot", false, "compact + split preset for the Windows report")
	fs.BoolVar(&o.redact, "redact", false, "replace identifying details in both reports with placeholders")
	fs.BoolVar(&o.yesElevate, "elevate", false, "relaunch the Windows check as Administrator without asking")
	fs.BoolVar(&o.noElevate, "no-elevate", false, "never offer to relaunch as Administrator")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	return o, inRange("days", o.days, 1, 90)
}

// ---------------------------------------------------------------------------
// PowerShell argument construction
// ---------------------------------------------------------------------------

func buildWindowsArgs(o winOpts) []string {
	// -SkipAdminCheck: this launcher owns the elevation decision, so the script must not
	// prompt (and spawn its own elevated copy pointing at a temp file we are about to delete).
	a := []string{"-SkipAdminCheck"}
	days, verb, split, maxKB := o.days, o.verbosity, o.split, o.maxPartKB
	if o.copilot {
		if verb == "" {
			verb = "Compact"
		}
		split = true
		if maxKB == 0 {
			maxKB = 40
		}
		if days == 0 {
			days = 3
		}
	}
	if days != 0 {
		a = append(a, "-DaysBack", fmt.Sprint(days))
	}
	if o.out != "" {
		a = append(a, "-OutputFolder", o.out)
	}
	if verb != "" {
		a = append(a, "-Verbosity", verb)
	}
	if o.maxUptime != 0 {
		a = append(a, "-MaxUptimeDays", fmt.Sprint(o.maxUptime))
	}
	if split {
		a = append(a, "-SplitOutput")
	}
	if maxKB != 0 {
		a = append(a, "-MaxPartKB", fmt.Sprint(maxKB))
	}
	if o.copilot {
		a = append(a, "-MaxParts", "3") // Copilot accepts at most 3 file uploads at a time
	}
	if o.integrity {
		a = append(a, "-IncludeIntegrityScan")
	}
	if o.battery {
		a = append(a, "-IncludeBatteryReport")
	}
	return append(a, o.raw...)
}

func buildOutlookArgs(o olOpts) []string {
	var a []string
	if o.days != 0 {
		a = append(a, "-DaysBack", fmt.Sprint(o.days))
	}
	if o.out != "" {
		a = append(a, "-OutputFolder", o.out)
	}
	if o.deep {
		a = append(a, "-DeepFolderScan")
	}
	if len(o.endpoints) > 0 {
		// The script splits on commas (powershell -File does not build arrays itself).
		a = append(a, "-AdditionalEndpoints", strings.Join(o.endpoints, ","))
	}
	if o.warn != 0 {
		a = append(a, "-FolderWarnThreshold", fmt.Sprint(o.warn))
	}
	if o.action != 0 {
		a = append(a, "-FolderActionThreshold", fmt.Sprint(o.action))
	}
	return append(a, o.raw...)
}

// ---------------------------------------------------------------------------
// Running the embedded scripts
// ---------------------------------------------------------------------------

var reportPathRE = regexp.MustCompile(`[A-Za-z]:\\[^\r\n"<>|?*]*?(?:HealthReport|OutlookHealthReport)_[^\r\n"<>|?*]*?\.md`)

// pathCapture tees child output so the final summary can list the files that were written.
type pathCapture struct{ buf bytes.Buffer }

func (p *pathCapture) Write(b []byte) (int, error) {
	if p.buf.Len() < 1<<20 {
		p.buf.Write(b)
	}
	return len(b), nil
}

func (p *pathCapture) Paths() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reportPathRE.FindAllString(p.buf.String(), -1) {
		m = strings.TrimSpace(m)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// writeScript writes with a UTF-8 BOM: Windows PowerShell 5.1 reads BOM-less files as the
// legacy ANSI code page, which corrupts any non-ASCII character in a script.
func writeScript(path string, content []byte) error {
	if bytes.HasPrefix(content, []byte{0xEF, 0xBB, 0xBF}) {
		return os.WriteFile(path, content, 0o600)
	}
	return os.WriteFile(path, append([]byte{0xEF, 0xBB, 0xBF}, content...), 0o600)
}

func powershellPath() (string, error) {
	if runtime.GOOS == "windows" {
		if sr := os.Getenv("SystemRoot"); sr != "" {
			p := filepath.Join(sr, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	if p, err := exec.LookPath("powershell.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("Windows PowerShell 5.1 (powershell.exe) was not found on this machine")
}

func runScript(name string, content []byte, args []string) (int, []string, error) {
	ps, err := powershellPath()
	if err != nil {
		return 1, nil, err
	}
	dir, err := os.MkdirTemp("", "healthcheck-")
	if err != nil {
		return 1, nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, name)
	if err := writeScript(path, content); err != nil {
		return 1, nil, err
	}
	full := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path}, args...)
	cmd := exec.Command(ps, full...)
	capt := &pathCapture{}
	prog := newProgress(countSections(content))
	w := &uiWriter{capt: capt, prog: prog}
	cmd.Stdout = w
	cmd.Stderr = w
	cmd.Stdin = os.Stdin
	runErr := cmd.Run()
	w.flush()
	prog.finish()
	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			code, runErr = ee.ExitCode(), nil
		} else {
			code = 1
		}
	}
	return code, capt.Paths(), runErr
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

type elevDecision int

const (
	proceedHere elevDecision = iota
	handedOff
	abort
)

func elevationFlow(cmdArgs []string, noElevate, yes bool) elevDecision {
	if isAdmin() || noElevate {
		return proceedHere
	}
	fmt.Println("Not running as Administrator: SMART counters, TPM, BitLocker, the Security log and")
	fmt.Println("minifilter details will be incomplete.")
	if !yes && !askYN("Relaunch elevated now (UAC prompt)?", true) {
		return proceedHere
	}
	if err := relaunchElevated(cmdArgs); err != nil {
		fmt.Println("Could not elevate:", err)
		if askYN("Continue without elevation?", true) {
			return proceedHere
		}
		return abort
	}
	fmt.Println("Continuing in the elevated window that just opened.")
	return handedOff
}

func cmdWindows(args []string) int {
	o, err := parseWindows(args)
	if err != nil {
		return usageErr(err)
	}
	cmdArgs := append([]string{"windows", "--no-elevate"}, args...)
	switch elevationFlow(cmdArgs, o.noElevate, o.yesElevate) {
	case handedOff:
		return 0
	case abort:
		return 1
	}
	fmt.Println("Running the Windows 11 health collector...")
	t0 := time.Now()
	code, paths, rerr := runScript(winScriptName, windowsScript, buildWindowsArgs(o))
	paths, note := applyRedaction(o.redact && rerr == nil && code == 0, paths)
	rc := printSummary("Windows 11 health check", code, paths, rerr, time.Since(t0))
	note()
	return rc
}

func cmdOutlook(args []string) int {
	o, err := parseOutlook(args)
	if err != nil {
		return usageErr(err)
	}
	if isAdmin() && !o.deelevated {
		switch offerNormalWindow(args, false) {
		case offerLaunched:
			return 0
		case offerCancel:
			return 1
		}
	} else if newOutlookRunning() && !outlookRunning() {
		fmt.Println(yellow("The NEW Outlook for Windows (olk.exe) is running, not classic Outlook."))
		fmt.Println("This check inspects classic Outlook (OUTLOOK.EXE). The new Outlook cannot be inspected this way,")
		fmt.Println("so only the network, antivirus and search sections would be collected.")
		fmt.Println(dim("To test classic Outlook: close the new Outlook, open classic Outlook, then continue."))
		fmt.Println()
		if ans := ask("Press Enter to continue, or type Q to quit", ""); strings.EqualFold(ans, "q") {
			return 1
		}
		fmt.Println()
	} else if !outlookRunning() {
		fmt.Println(yellow("Outlook is not open."))
		fmt.Println("Open Outlook now for full results; otherwise only the registry, network, search and event-log")
		fmt.Println("sections will be collected.")
		fmt.Println()
		if ans := ask("Open Outlook, then press Enter to continue (or Q to quit)", ""); strings.EqualFold(ans, "q") {
			return 1
		}
		fmt.Println()
	}
	fmt.Println("Running the Outlook health collector...")
	t0 := time.Now()
	code, paths, rerr := runScript(olScriptName, outlookScript, buildOutlookArgs(o))
	paths, note := applyRedaction(o.redact && rerr == nil && code == 0, paths)
	rc := printSummary("Outlook health check", code, paths, rerr, time.Since(t0))
	note()
	return rc
}

func cmdAll(args []string) int {
	o, err := parseAll(args)
	if err != nil {
		return usageErr(err)
	}
	if isAdmin() {
		oa := []string{}
		if o.days != 0 {
			oa = append(oa, "--days", fmt.Sprint(o.days))
		}
		if o.out != "" {
			oa = append(oa, "--out", o.out)
		}
		if o.redact {
			oa = append(oa, "--redact")
		}
		if offerNormalWindow(oa, true) == offerCancel {
			return 1
		}
		wa := []string{"--no-elevate"}
		wa = appendCommon(wa, o)
		return cmdWindows(wa)
	}
	// Not elevated: Outlook first (needs this session), then hand the Windows check to an elevated window.
	oa := []string{}
	if o.days != 0 {
		oa = append(oa, "--days", fmt.Sprint(o.days))
	}
	if o.out != "" {
		oa = append(oa, "--out", o.out)
	}
	if o.redact {
		oa = append(oa, "--redact")
	}
	rc := cmdOutlook(oa)
	fmt.Println()
	wa := appendCommon(nil, o)
	if o.noElevate {
		wa = append(wa, "--no-elevate")
	}
	if o.yesElevate {
		wa = append(wa, "--elevate")
	}
	if wrc := cmdWindows(wa); wrc != 0 && rc == 0 {
		rc = wrc
	}
	return rc
}

func appendCommon(a []string, o allOpts) []string {
	if o.days != 0 {
		a = append(a, "--days", fmt.Sprint(o.days))
	}
	if o.out != "" {
		a = append(a, "--out", o.out)
	}
	if o.copilot {
		a = append(a, "--copilot")
	}
	if o.redact {
		a = append(a, "--redact")
	}
	return a
}

var collectorVerRe = regexp.MustCompile(`Collector version:\**\s*([0-9][0-9.]*)`)

// collectorVersion extracts the collector version declared inside an embedded script.
func collectorVersion(b []byte) string {
	if m := collectorVerRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return "?"
}

func launcherID() string { return fmt.Sprintf("HealthCheck %s (built %s)", version, buildDate) }

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func cmdVersion() int {
	fmt.Printf("HealthCheck %s (built %s, %s/%s, %s)\n", version, buildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("  Windows collector %s, Outlook collector %s\n", collectorVersion(windowsScript), collectorVersion(outlookScript))
	fmt.Printf("  %-32s %6d bytes  sha256 %s\n", winScriptName, len(windowsScript), sha(windowsScript))
	fmt.Printf("  %-32s %6d bytes  sha256 %s\n", olScriptName, len(outlookScript), sha(outlookScript))
	return 0
}

const helpText = `HealthCheck - Windows 11 and Outlook health collectors in one executable.

USAGE
  HealthCheck                      interactive menu
  HealthCheck windows [flags]      Windows 11 health check  (best run as Administrator)
  HealthCheck outlook [flags]      Outlook slowness check   (run as the NORMAL user, Outlook open)
  HealthCheck all     [flags]      Outlook check now, then the Windows check elevated
  HealthCheck version              version and SHA-256 of the embedded scripts

WINDOWS FLAGS
  --days N              event lookback, 1-365 (default 7)
  --verbosity V         compact | standard | full
  --split               split output into several files; --max-part-kb N sets the size (20-5000)
  --copilot             preset for chat upload: compact + at most 3 parts (Copilot upload limit) + 3-day window
  --max-uptime-days N   restart-cadence policy, 1-90 (default 7)
  --integrity           add DISM / SFC read-only integrity checks (5-20 min)
  --battery             add battery report (laptops)
  --redact              replace host/user names, IPs, MACs, e-mails and serials with placeholders (map saved privately)
  --out DIR             output folder (default: Desktop)
  --elevate | --no-elevate   skip the prompt: always / never relaunch as Administrator

OUTLOOK FLAGS
  --days N              event lookback, 1-90 (default 14)
  --deep-folder-scan    all stores, deeper subfolders (slower)
  --endpoint HOST       extra host to test, e.g. on-prem Exchange (repeatable)
  --folder-warn N / --folder-action N    folder item-count thresholds
  --out DIR             output folder (default: Desktop)
  --redact              replace identifying details with placeholders (map saved privately)

Anything after a bare "--" is passed straight to the PowerShell script.
Reports contain hostnames, usernames, paths and installed software: review before sharing.
`

func usageErr(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	fmt.Fprintln(os.Stderr, "run 'HealthCheck help' for usage")
	return 2
}

// ---------------------------------------------------------------------------
// Interactive helpers
// ---------------------------------------------------------------------------

var stdin = bufio.NewReader(os.Stdin)

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s %s %s ", cyan(glyph("›", ">")), prompt, dim("["+def+"]:"))
	} else {
		fmt.Printf("%s %s: ", cyan(glyph("›", ">")), prompt)
	}
	line, _ := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askYN(prompt string, defYes bool) bool {
	d := "y"
	if !defYes {
		d = "n"
	}
	ans := strings.ToLower(ask(prompt+" (y/n)", d))
	return strings.HasPrefix(ans, "y")
}

func menu() int {
	for {
		fmt.Println()
		banner()
		fmt.Println()
		fmt.Println("  " + bold("What would you like to run?"))
		fmt.Println()
		adminNote := ""
		if !isAdmin() {
			adminNote = "  " + yellow("will ask to elevate")
		}
		fmt.Printf("   %s  %-26s %s%s\n", cyan("[1]"), "Windows 11 health check", dim("system, drivers, filters, security"), adminNote)
		fmt.Printf("   %s  %-26s %s\n", cyan("[2]"), "Outlook slowness check", dim("run as the affected user, Outlook open"))
		fmt.Printf("   %s  %-26s %s\n", cyan("[3]"), "Both", dim("Outlook first, then Windows"))
		fmt.Printf("   %s  %s\n", cyan("[Q]"), "Quit")
		fmt.Println()
		switch strings.ToLower(ask("Choose", "")) {
		case "1":
			var a []string
			if askYN("Optimise report size for chat-assistant (Copilot) upload?", true) {
				a = append(a, "--copilot")
			}
			a = askRedact(a)
			return cmdWindows(a)
		case "2":
			var a []string
			if askYN("Deep folder scan (slower, all stores)?", false) {
				a = append(a, "--deep-folder-scan")
			}
			if ep := ask("Extra Exchange/Autodiscover host to test (blank = none)", ""); ep != "" {
				a = append(a, "--endpoint", ep)
			}
			a = askRedact(a)
			return cmdOutlook(a)
		case "3":
			var a []string
			if askYN("Optimise the Windows report for chat-assistant upload?", true) {
				a = append(a, "--copilot")
			}
			a = askRedact(a)
			return cmdAll(a)
		case "q", "quit", "exit":
			return 0
		}
		fmt.Println("Please enter 1, 2, 3 or Q.")
	}
}

// ---------------------------------------------------------------------------

func dispatch(args []string) int {
	if len(args) == 0 {
		return menu()
	}
	rest := args[1:]
	switch strings.ToLower(args[0]) {
	case "windows", "win", "w":
		return cmdWindows(rest)
	case "outlook", "ol", "o":
		return cmdOutlook(rest)
	case "all", "both":
		return cmdAll(rest)
	case "version", "--version", "-v":
		return cmdVersion()
	case "help", "--help", "-h", "-?", "/?":
		fmt.Print(helpText)
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
	fmt.Fprint(os.Stderr, helpText)
	return 2
}

func main() {
	initUI()
	os.Setenv("HEALTHCHECK_LAUNCHER", launcherID()) // recorded in each report header
	setConsoleTitle(fmt.Sprintf("HealthCheck %s", version))
	if len(os.Args) > 1 {
		switch strings.ToLower(os.Args[1]) {
		case "windows", "win", "w", "outlook", "ol", "o", "all", "both":
			banner()
		}
	}
	code := dispatch(os.Args[1:])
	pauseIfOwnConsole() // keeps the window open when launched by double-click or UAC
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Elevated start: Outlook cannot be inspected from an administrator window
// ---------------------------------------------------------------------------

type offerResult int

const (
	offerLaunched offerResult = iota // the Outlook check was opened in a normal window
	offerContinue                    // carry on in this window
	offerCancel                      // stop
)

// offerNormalWindow explains why an elevated window cannot inspect Outlook and offers to run the
// Outlook check in a normal (non-elevated) window instead. both=true means the caller will go on
// to run the Windows check here regardless, so "continue" means "skip Outlook".
func offerNormalWindow(outlookArgs []string, both bool) offerResult {
	fmt.Println(yellow("This window is running as Administrator."))
	fmt.Println("Windows does not let an elevated program reach a normal program's automation interface, so")
	fmt.Println("Outlook's accounts, add-ins, data files and folders cannot be read from here.")
	fmt.Println(dim("Note: the normal window runs as the SAME account. If you are an administrator signed in as a"))
	fmt.Println(dim("different person from the affected user, ask that user to run the Outlook check themselves."))
	fmt.Println()
	fmt.Printf("   %s  Open the Outlook check in a normal window %s\n", cyan("[1]"), green("(recommended)"))
	if both {
		fmt.Printf("   %s  Skip the Outlook check and run only the Windows check\n", cyan("[2]"))
	} else {
		fmt.Printf("   %s  Continue here with partial results (network, search and event logs only)\n", cyan("[2]"))
	}
	fmt.Printf("   %s  Cancel\n", cyan("[Q]"))
	fmt.Println()
	for {
		switch strings.ToLower(ask("Choose", "1")) {
		case "1":
			args := append([]string{"outlook", "--deelevated"}, outlookArgs...)
			if err := relaunchUnelevated(args); err != nil {
				fmt.Println(red("Could not open a normal window: ") + err.Error())
				fmt.Println(dim("Close this window and run HealthCheck again from a normal one."))
				continue
			}
			fmt.Println(green(glyph("✔", "[ok]")) + " Opened the Outlook check in a separate window. Open Outlook there if prompted.")
			fmt.Println()
			if both {
				return offerContinue // the Windows check carries on here
			}
			return offerLaunched
		case "2":
			fmt.Println()
			return offerContinue
		case "q", "quit":
			fmt.Println("Cancelled.")
			return offerCancel
		}
		fmt.Println("Please enter 1, 2 or Q.")
	}
}

// ---------------------------------------------------------------------------
// Redaction (see redact.go)
// ---------------------------------------------------------------------------

// askRedact offers the redaction option in the menu. It defaults to yes: a report that is shared
// with an outside service should not carry host names, user names, addresses or serial numbers.
func askRedact(a []string) []string {
	fmt.Println(dim("  Redaction replaces host/user names, IP and MAC addresses, e-mails and serial numbers with"))
	fmt.Println(dim("  placeholders (HOST-1, IP-PRIV-1...). A private map file is saved so you can translate back."))
	if askYN("Redact identifying details before you share the report?", true) {
		a = append(a, "--redact")
	}
	return a
}

// applyRedaction rewrites the reports when on is true. It returns the (possibly renamed) report paths and
// a function that prints what happened; callers print it after the summary panel so it is not scrolled away.
func applyRedaction(on bool, paths []string) ([]string, func()) {
	nothing := func() {}
	if !on || len(paths) == 0 {
		return paths, nothing
	}
	stamp := time.Now().Format("20060102-150405")
	np, mapPath, summary, err := redactFiles(paths, identityFromEnv(), stamp)
	if err != nil {
		return paths, func() {
			fmt.Println()
			fmt.Println(red(glyph("✖", "[x]")) + " " + bold("Redaction failed: ") + err.Error())
			fmt.Println(yellow("  The reports were NOT redacted. Do not share them until you have reviewed or redacted them."))
		}
	}
	return np, func() {
		fmt.Println()
		fmt.Println(green(glyph("✔", "[ok]")) + " " + bold("Redacted: ") + summary)
		fmt.Println("  Map of placeholders to real values: " + mapPath)
		fmt.Println(yellow("  Keep that map file private. Do NOT upload it."))
		fmt.Println(dim("  Redaction is best-effort. Skim the report for other names (colleagues, projects) before sharing."))
	}
}
