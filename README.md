# HealthCheck

A read-only Windows 11 health collector and Outlook slowness check. It gathers evidence, flags it
OK / WATCH / ACTION, and writes Markdown reports with an analysis prompt built in, so an AI assistant
such as Microsoft Copilot can turn the evidence into a structured assessment.

**You do not have to trust a binary to use it.** The product is the two PowerShell scripts in
[`scripts/`](scripts/). `HealthCheck.exe` is only a convenience wrapper around them. Read the scripts,
run them directly, or build the exe yourself.

| Component | File | Version |
| --- | --- | --- |
| Windows 11 collector (36 sections) | [`scripts/Get-Windows11HealthReport.ps1`](scripts/Get-Windows11HealthReport.ps1) | 2.5 |
| Outlook slowness collector (12 sections) | [`scripts/Get-OutlookHealthReport.ps1`](scripts/Get-OutlookHealthReport.ps1) | 1.3 |
| Launcher (menu, progress UI, elevation, redaction) | [`main.go`](main.go), [`ui.go`](ui.go), [`redact.go`](redact.go), `platform_*.go` | 1.4.0 |

## Three ways to use it, from least to most trust required

1. **Read the scripts, then run them directly.** No exe involved:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Get-Windows11HealthReport.ps1 -Verbosity compact
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Get-OutlookHealthReport.ps1
   ```

   Run the Windows script from an elevated PowerShell for full results. Run the Outlook script from a
   **normal** (non-elevated) PowerShell with classic Outlook open.
2. **Build the exe yourself** from this source: see [docs/BUILDING.md](docs/BUILDING.md). The build is
   `-trimpath` with no third-party modules, so you can compare your hash with the release's.
3. **Download the release exe** and verify it: see [docs/VERIFY.md](docs/VERIFY.md). Releases are built by
   GitHub Actions from a tagged commit and carry a SHA-256 file and a build provenance attestation.

## What it does and does not do

It reads system state and writes report files. It does not change settings, install, repair or upload
anything. The exact commands, files written and network connections are listed in
[docs/WHAT-IT-DOES.md](docs/WHAT-IT-DOES.md), with the line of code each comes from, so you can check them.

## Using the exe

Run `HealthCheck.exe` and pick **1** Windows check, **2** Outlook check or **3** both. Or use the command line:

```
HealthCheck windows --copilot
HealthCheck outlook --deep-folder-scan --endpoint mail.contoso.com
HealthCheck all --copilot --redact
HealthCheck version      (prints the SHA-256 of each embedded script)
```

Reports go to your Desktop (or `--out DIR`). With `--copilot` the Windows report is compact and split into
at most three files, because Copilot accepts three uploads at a time. Attach all the files from one run
and say "Analyse these diagnostic files."

## Before you upload a report to an AI service

A report contains the hostname, usernames, serial numbers, IP addresses, file paths, installed software and
parts of event-log messages. Read it first and remove anything you should not share. Use your organisation's
approved AI service.

The menu asks **"Redact identifying details?"** (default yes), and the command line has `--redact`. It replaces
host and user names, IP and MAC addresses, e-mails, domain SIDs and serial numbers with placeholders such as
`HOST-1` and `IP-PRIV-2`, and saves a private map so you can translate findings back. It is best-effort: see
[docs/REDACTION.md](docs/REDACTION.md) for what it does and does not catch.

## Antivirus warnings

Small unsigned programs that embed PowerShell can trigger generic machine-learning detections. See
[docs/ANTIVIRUS.md](docs/ANTIVIRUS.md) for what to check and how to report a false positive.

## Reporting problems and security issues

See [SECURITY.md](SECURITY.md). Version history is in [CHANGELOG.md](CHANGELOG.md). Design background is in
[docs/Technical-Explainer.md](docs/Technical-Explainer.md).

## Licence

MIT. See [LICENSE](LICENSE). Provided as is, with no warranty. The AI analysis of a report can be wrong;
verify important recommendations and take a backup before acting on anything invasive.
