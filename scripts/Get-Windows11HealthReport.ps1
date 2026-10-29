<#
.SYNOPSIS
    Collects a comprehensive Windows 11 health, stability and configuration snapshot
    into a single Markdown file, prefixed with an AI analysis prompt.

.DESCRIPTION
    Gathers OS/hardware inventory, disk and SMART health, event log errors and criticals,
    crash/bugcheck history, boot performance, update history, driver and device faults,
    service failures, scheduled task failures, performance snapshot, network state,
    security posture and reliability history.

    Everything is written to ONE file. The top of that file contains a structured prompt
    telling an AI assistant how to analyse the data, what to report, and how to justify
    its recommendations. You upload/paste the single file and the AI does the rest.

.PARAMETER DaysBack
    How far back to pull events. Default 7. Use 14-30 for intermittent issues.

.PARAMETER OutputFolder
    Where to write the report. Defaults to the Desktop.

.PARAMETER MaxEventsPerQuery
    Hard cap on events retrieved per log query (protects against huge files). Default 3000.

.PARAMETER DetailEventCount
    How many individual events (with full messages) to include per section. Default 25.

.PARAMETER IncludeIntegrityScan
    Also runs DISM /CheckHealth and SFC /VERIFYONLY. Adds 5-20 minutes.

.PARAMETER IncludeBatteryReport
    Also generates a powercfg battery report alongside the main file (laptops).

.EXAMPLE
    .\Get-Windows11HealthReport.ps1

.EXAMPLE
    .\Get-Windows11HealthReport.ps1 -DaysBack 30 -IncludeIntegrityScan -IncludeBatteryReport

.NOTES
    Run as Administrator for full coverage. The script will offer to self-elevate.
    PRIVACY: the output contains hostname, usernames, serial numbers, IP addresses and
    installed software. Review/redact before sharing with a third-party AI service.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$DaysBack = 7,
    [string]$OutputFolder = [Environment]::GetFolderPath('Desktop'),
    [ValidateRange(50, 20000)][int]$MaxEventsPerQuery = 3000,
    [ValidateRange(5, 200)][int]$DetailEventCount = 25,
    [ValidateSet('Compact', 'Standard', 'Full')][string]$Verbosity = 'Standard',
    [ValidateRange(1, 90)][int]$MaxUptimeDays = 7,
    [switch]$SplitOutput,
    [ValidateRange(20, 5000)][int]$MaxPartKB = 80,
    [ValidateRange(0, 20)][int]$MaxParts = 0,   # 0 = unlimited. Copilot accepts 3 uploads at a time: use -MaxParts 3
    [switch]$IncludeIntegrityScan,
    [switch]$IncludeBatteryReport,
    [switch]$SkipAdminCheck
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin -and -not $SkipAdminCheck) {
    Write-Warning "Not running elevated. Disk health, TPM, BitLocker and Security log data will be incomplete."
    $answer = Read-Host "Relaunch as Administrator? (Y/N)"
    if ($answer -match '^(y|yes)$') {
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
                     '-DaysBack', $DaysBack, '-OutputFolder', "`"$OutputFolder`"",
                     '-MaxEventsPerQuery', $MaxEventsPerQuery, '-DetailEventCount', $DetailEventCount)
        if ($IncludeIntegrityScan)  { $argList += '-IncludeIntegrityScan' }
        if ($IncludeBatteryReport)  { $argList += '-IncludeBatteryReport' }
        $host_exe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
        Start-Process $host_exe -Verb RunAs -ArgumentList $argList
        return
    }
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

$Stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportPath = Join-Path $OutputFolder "HealthReport_$($env:COMPUTERNAME)_$Stamp.md"
$StartTime  = Get-Date
$Since      = $StartTime.AddDays(-$DaysBack)
$Report     = [System.Text.StringBuilder]::new()

# Verbosity presets. These cap table rows, message length and event detail so the
# finished file stays inside the upload limits of chat assistants.
switch ($Verbosity) {
    'Compact'  { $script:TableCap = 12; $script:MsgLen = 180; $script:TopGroups = 10; $script:DefDetail = 6  }
    'Standard' { $script:TableCap = 25; $script:MsgLen = 320; $script:TopGroups = 20; $script:DefDetail = 12 }
    'Full'     { $script:TableCap = 200; $script:MsgLen = 600; $script:TopGroups = 40; $script:DefDetail = 40 }
}
if (-not $PSBoundParameters.ContainsKey('DetailEventCount')) { $DetailEventCount = $script:DefDetail }

function Add-Line { param([string]$Text = '') [void]$Report.AppendLine($Text) }

function Get-ShortText {
    param([string]$Text, [int]$Max = 400)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    if ($script:MsgLen -and $Max -gt $script:MsgLen) { $Max = $script:MsgLen }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + ' ...[truncated]' }
    return $t
}

function Get-FilterAltitudeClass {
    # Maps a minifilter altitude to its Microsoft-defined load-order group.
    param([string]$Altitude)
    $a = 0.0
    if (-not [double]::TryParse($Altitude, [ref]$a)) { return 'Unknown' }
    switch ($a) {
        { $_ -ge 400000 } { 'Top (unclassified-high)';        break }
        { $_ -ge 360000 } { 'Activity Monitor';               break }
        { $_ -ge 340000 } { 'Undelete';                       break }
        { $_ -ge 320000 } { 'ANTI-VIRUS';                     break }
        { $_ -ge 300000 } { 'Replication';                    break }
        { $_ -ge 280000 } { 'Continuous Backup';              break }
        { $_ -ge 260000 } { 'Content Screener';               break }
        { $_ -ge 240000 } { 'Quota Management';               break }
        { $_ -ge 220000 } { 'System Recovery';                break }
        { $_ -ge 200000 } { 'Cluster File System';            break }
        { $_ -ge 180000 } { 'HSM';                            break }
        { $_ -ge 170000 } { 'Imaging (compressed container)'; break }
        { $_ -ge 160000 } { 'Compression';                    break }
        { $_ -ge 140000 } { 'ENCRYPTION';                     break }
        { $_ -ge 130000 } { 'Virtualization';                 break }
        { $_ -ge 120000 } { 'Physical Quota';                 break }
        { $_ -ge 100000 } { 'Open File';                      break }
        { $_ -ge  80000 } { 'Security Enhancer';              break }
        { $_ -ge  60000 } { 'Copy Protection';                break }
        { $_ -ge  40000 } { 'Bottom';                         break }
        { $_ -ge  20000 } { 'System';                         break }
        default           { 'Below defined range' }
    }
}

function Get-DriverSigner {
    # Resolves a service ImagePath to a file and returns the signing organisation.
    # Returns 'FILE MISSING' for orphaned registrations - a key diagnostic signal.
    param([string]$ImagePath, [string]$ServiceName)
    # Kernel drivers often have no ImagePath value: Windows then loads System32\drivers\<service>.sys
    if ([string]::IsNullOrWhiteSpace($ImagePath)) {
        if ([string]::IsNullOrWhiteSpace($ServiceName)) { return 'no ImagePath' }
        $ImagePath = "$env:SystemRoot\System32\drivers\$ServiceName.sys"
    }
    $p = $ImagePath -replace '^\\\?\?\\', ''
    $p = $p -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    $p = $p -replace '^system32\\', "$env:SystemRoot\system32\"
    $p = [Environment]::ExpandEnvironmentVariables($p)
    if ($p -notmatch '^[A-Za-z]:\\') { $p = Join-Path $env:SystemRoot $p }
    if (-not (Test-Path $p)) { return 'FILE MISSING' }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop
        if ($sig.SignerCertificate) {
            $org = ($sig.SignerCertificate.Subject -split ',' |
                    Where-Object { $_ -match '^\s*O=' } | Select-Object -First 1)
            if (-not $org) { $org = ($sig.SignerCertificate.Subject -split ',')[0] }
            return (($org -replace '^\s*(O|CN)=', '').Trim('" ') + " [$($sig.Status)]")
        }
        return "UNSIGNED [$($sig.Status)]"
    }
    catch { return 'signature check failed' }
}

function New-Metric {
    # Evaluates a metric safely and assigns a triage flag. Never throws.
    param([string]$Name, [scriptblock]$Compute, [scriptblock]$Assess)
    $v = try { & $Compute } catch { 'unavailable' }
    # NB: never compare with -eq '' / -ne 'text' here. PowerShell coerces the right operand to the
    # left operand's type, so 0 -eq '' and $false -eq '' are True and $true -ne 'unavailable' is False.
    $missing = ($null -eq $v) -or (($v -is [string]) -and ([string]::IsNullOrEmpty($v) -or $v -ceq 'unavailable'))
    if ($missing) { $v = 'unavailable' }
    $f = 'INFO'
    if ($Assess -and -not $missing) { $f = try { & $Assess $v } catch { 'INFO' } }
    [PSCustomObject]@{ Metric = $Name; Value = "$v"; Flag = $f }
}

function Add-Section {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][scriptblock]$Collector,
        [string]$Purpose
    )
    Write-Host "  -> $Title" -ForegroundColor Cyan
    Add-Line ''
    Add-Line "## $Title"
    if ($Purpose) { Add-Line "*Analyst note: $Purpose*"; Add-Line '' }
    Add-Line '```text'
    try {
        $out = & $Collector 2>&1 | Out-String -Width 220
        if ([string]::IsNullOrWhiteSpace($out)) { $out = '(no data returned)' }
        Add-Line $out.TrimEnd()
    }
    catch {
        Add-Line "COLLECTION ERROR: $($_.Exception.Message)"
    }
    Add-Line '```'
}

function Get-EventsSafe {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [int[]]$Level,
        [int[]]$Id,
        [string[]]$ProviderName,
        [int]$Days = $DaysBack,
        [int]$Max  = $MaxEventsPerQuery
    )
    $filter = @{ LogName = $LogName; StartTime = (Get-Date).AddDays(-$Days) }
    if ($Level)        { $filter['Level']        = $Level }
    if ($Id)           { $filter['Id']           = $Id }
    if ($ProviderName) { $filter['ProviderName'] = $ProviderName }
    try   { @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop) }
    catch { @() }
}

function Get-EventGroupKey {
    # Grouping key for the frequency table. Windows Error Reporting 1001 is one event ID used for
    # every kind of fault, so grouping by ID alone hides a flood of one specific fault (e.g. LiveKernelEvent 193).
    param($e)
    if ($e.ProviderName -eq 'Windows Error Reporting' -and $e.Id -eq 1001) {
        $n  = if ($e.Message -match 'Event Name:\s*(\S+)') { $Matches[1] } else { '' }
        # P1 only distinguishes LiveKernelEvent fault codes; for other WER events it is a long free-text string.
        $p1 = if ($n -eq 'LiveKernelEvent' -and $e.Message -match 'P1:\s*(\S+)') { $Matches[1] } else { '' }
        return "Windows Error Reporting|1001|$n|$p1"
    }
    return "$($e.ProviderName)|$($e.Id)"
}

function Format-EventReport {
    param([array]$Events, [int]$DetailCount = $DetailEventCount, [int]$TopGroups = $script:TopGroups)

    if (-not $Events -or $Events.Count -eq 0) { return 'No matching events in the selected window.' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("Total matching events: $($Events.Count)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- FREQUENCY (most repeated first) ---')

    $freq = $Events | Group-Object -Property { Get-EventGroupKey $_ } | Sort-Object Count -Descending |
        Select-Object -First $TopGroups @{n = 'Count'; e = { $_.Count } },
            @{n = 'Provider'; e = { $_.Group[0].ProviderName } },
            @{n = 'EventID';  e = { $_.Group[0].Id } },
            @{n = 'FaultType'; e = { $p = $_.Name -split '\|'; if ($p.Count -ge 3) { $t = $p[2]; if ($p.Count -ge 4 -and $p[3]) { $t += " P1=$($p[3])" }; if ($t.Length -gt 40) { $t.Substring(0,40) } else { $t } } else { '' } } },
            @{n = 'Level';    e = { $_.Group[0].LevelDisplayName } },
            @{n = 'FirstSeen'; e = { ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated } },
            @{n = 'LastSeen';  e = { ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated } },
            @{n = 'SampleMessage'; e = { Get-ShortText $_.Group[0].Message 120 } }

    [void]$sb.AppendLine((($freq | Format-Table -AutoSize -Wrap | Out-String -Width 220).TrimEnd()))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("--- MOST RECENT $DetailCount EVENTS WITH DISTINCT MESSAGES ---")
    [void]$sb.AppendLine('(identical repeats are collapsed; see the frequency table above for counts)')

    $seen = @{}
    $shown = 0
    foreach ($e in ($Events | Sort-Object TimeCreated -Descending)) {
        if ($shown -ge $DetailCount) { break }
        $gk  = Get-EventGroupKey $e
        $key = if ($gk -like 'Windows Error Reporting|1001|*') { $gk } else { "$gk|" + (Get-ShortText $e.Message 100) }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $shown++
        [void]$sb.AppendLine(('[{0:yyyy-MM-dd HH:mm:ss}] {1} | ID {2} | {3}' -f `
            $e.TimeCreated, $e.LevelDisplayName, $e.Id, $e.ProviderName))
        [void]$sb.AppendLine('    ' + (Get-ShortText $e.Message 450))
    }
    return $sb.ToString()
}

Write-Host ""
Write-Host "Windows 11 Health Collector" -ForegroundColor Green
Write-Host "Window: last $DaysBack day(s)  |  Elevated: $IsAdmin" -ForegroundColor Green
Write-Host ""

# ===========================================================================
# PART 1 - THE AI ANALYSIS PROMPT (single-quoted here-string, no interpolation)
# ===========================================================================
$AiPrompt = @'
<!-- ======================================================================
     AI ANALYSIS PROMPT - READ THIS FIRST, THEN ANALYSE THE DATA BELOW
     ====================================================================== -->

# INSTRUCTIONS FOR THE AI ASSISTANT

## 1. Your role
You are a senior Windows platform engineer performing a health assessment of a single
Windows 11 endpoint. You have been given one machine-generated diagnostic file. Everything
after the marker `=== BEGIN COLLECTED DATA ===` is raw evidence collected from that machine.
Treat it as the sole source of truth. Do not invent events, IDs, timestamps or values that
do not appear in the data.

## 1b. Handling incomplete or truncated evidence - IMPORTANT

This file may be truncated by your platform's upload limit, or delivered to you as one of
several parts. Either way:

- **Always produce the report.** Analyse whatever evidence you actually received. A partial
  assessment that is clearly labelled as partial is useful; a refusal is not.
- Under no circumstances refuse to analyse on the grounds that the evidence is incomplete.
  The instruction not to invent data means you must not fabricate events, timestamps or
  values that you were not given. It does **not** mean you must have every section.
- If a section is absent, say so in section H (Data Gaps) by name, state what you could not
  assess as a result, and lower your stated confidence accordingly. Then move on.
- The TRIAGE DIGEST near the top of PART 1 contains metrics computed on the machine itself.
  If the raw evidence sections are missing or cut off, the digest alone is enough to produce
  a scorecard, findings and recommendations - use it and say that is what you did.
- If the text ends mid-sentence, treat everything before the cut as valid evidence and note
  where the truncation occurred.
- If you are told more parts are coming, acknowledge briefly and wait. Once no further parts
  are arriving, analyse what you have.

## 2. How to reason
- Work from evidence to conclusion, never the reverse. Every finding must cite concrete
  evidence: the section name, event ID, provider, timestamp, count, or measured value.
- Distinguish **correlation** from **causation**. If two things co-occur, say so and label
  the causal link as a hypothesis with a confidence level.
- Prioritise by *impact x likelihood*, not by how alarming an error message sounds. Many
  Windows errors are benign noise (e.g. routine DCOM 10016, isolated Kernel-EventTracing).
  Explicitly call out noise so the reader does not chase it.
- Weight repetition and recency: an error occurring 400 times in 48 hours matters more than
  a single error 6 days ago.
- Cross-reference sections. Example: storage errors + slow boot + high disk queue + SMART
  reallocated sectors is one story, not four findings.
- State your uncertainty. If the data is insufficient to reach a conclusion, say what
  additional data you would need and how to collect it.

## 3. Severity model (use these exact labels)
- **CRITICAL** - Active or imminent data loss, hardware failure, security compromise, or
  repeated unplanned outages. Act within 24 hours.
- **HIGH** - Significant instability, degraded protection, or a fault that will worsen.
  Act within 1 week.
- **MEDIUM** - Measurable performance/reliability drag or configuration drift. Act within 30 days.
- **LOW** - Hygiene, optimisation, or best-practice gaps. Act opportunistically.
- **INFORMATIONAL / NOISE** - Present in the logs but not actionable. Explain why.

## 4. Required output structure
Produce your report in exactly this order, using Markdown headings:

### A. Executive Summary
Maximum 200 words, written for a non-technical reader. State the overall verdict
(Healthy / Minor Issues / Degraded / At Risk / Critical), the single most important thing
to do next, and whether the machine is safe to keep using as-is.

### B. Health Scorecard
A table scoring each domain 0-10 with a one-line justification and the evidence that
drove the score:

| Domain | Score /10 | Verdict | Key Evidence |
|---|---|---|---|
| Stability (crashes, reboots) | | | |
| Storage & Filesystem | | | |
| Memory & CPU | | | |
| Boot & Shutdown Performance | | | |
| Drivers & Devices | | | |
| Filesystem Filter Stack | | | |
| Network Filter Stack | | | |
| Windows Update & Servicing | | | |
| Services & Scheduled Tasks | | | |
| Networking | | | |
| Security Posture | | | |
| Configuration Hygiene | | | |
| **Overall** | | | |

State your scoring rubric in one sentence so the score is reproducible.

### C. Findings
One subsection per finding, ordered CRITICAL -> LOW. Use this template:

**F-01 | [SEVERITY] | Short title**
- **Observation:** what the data literally shows.
- **Evidence:** section name(s), event IDs, providers, counts, first/last seen timestamps,
  measured values. Quote the specific lines you relied on.
- **Interpretation:** what this means technically.
- **Likely root cause:** with confidence High / Medium / Low, and competing hypotheses if any.
- **Impact if unaddressed:** concrete consequence and realistic time horizon.

### D. Correlation & Timeline Analysis
Build a chronological narrative of the significant events. Identify clusters - do errors
concentrate around boot, around a specific update installation, around a driver install,
or at a particular time of day? Explicitly note any event that immediately precedes
bugchecks or unexpected shutdowns.

### E. Recommendations
Ordered by priority. For each one:

| # | Recommendation | Addresses | Priority | Effort | Risk | Reboot? |
|---|---|---|---|---|---|---|

Then, beneath the table, for each recommendation give:
- **Justification:** why this specific action, tied to the evidence in the findings.
- **Why this over the alternatives:** name at least one option you rejected and why.
- **Exact steps:** the PowerShell commands, GUI path, or vendor action required.
- **Verification:** how to confirm it worked (specific command, event ID, or metric that
  should change), and over what observation window.
- **Rollback:** how to undo it if the change causes problems.

Never recommend a destructive action (reinstall, reset, disk wipe, registry surgery,
driver rollback) without first listing the non-destructive diagnostics that should be
attempted first, and without an explicit data-backup prerequisite.

### F. Quick Wins
Up to 5 low-risk, high-value actions that can be completed in under 30 minutes total.

### G. Watch List
Items that are not yet problems but should be monitored, with the specific threshold or
signal that would escalate them to a finding.

### H. Data Gaps & Confidence Statement
What the collection did NOT capture, what that prevents you from concluding, and your
overall confidence in this assessment (High / Medium / Low) with reasoning.

## 4a. Uptime and last-reboot claims - do not trust the raw WMI value alone

Windows 11 ships with Fast Startup enabled by default. Its "shutdown" hibernates the kernel
session rather than terminating it, so `Win32_OperatingSystem.LastBootUpTime` (and the
`UptimeDays_WMI` / "Uptime per WMI tick counter (days)" figures in this report) can silently
anchor to the last true cold boot and understate every Fast Startup cycle since. Section 07
contains a "Boot/Uptime Accuracy Cross-Check" that compares this against Event ID 6005
(EventLog service start), which does reset on every power-on including Fast Startup resumes.

- If that cross-check reports Fast Startup enabled with a discrepancy, use the EventLog-based
  figure for any claim about "how long has this machine been running" or "how recently was it
  restarted" - not the raw WMI value.
- Do not flag the discrepancy itself as a fault. It is expected Windows behaviour, not a
  finding, unless the user has a specific reason to need Fast Startup disabled (e.g. dual-boot,
  BitLocker key rotation issues, or firmware that mishandles hybrid resume).
- If you cite an uptime or "last rebooted" figure anywhere in your report (Executive Summary,
  Scorecard, Findings, Timeline), cite the reconciled one and say which source it came from.

## 4a-ii. Restart cadence is an organisational policy - enforce it as a finding

This collection was run with an expected restart interval of every $MaxUptimeDays day(s)
(recorded in the report header and in the digest as "Restart cadence policy" /
"Restart cadence compliance"). This is a stated organisational expectation, not merely
informational - if the reconciled true uptime (section 07's cross-check, NOT the raw WMI
figure) exceeds it, raise this as a genuine finding rather than a passing remark.

- **Severity tiering** (uptime measured against the configured interval):
  - Up to 1x the interval: no finding - compliant.
  - 1x-3x the interval: **LOW-MEDIUM**, scaled by how far over. Frame as a hygiene / policy
    drift issue.
  - Over 3x the interval: **MEDIUM-HIGH**. At this point treat it as a genuine performance
    and patch-compliance risk, not just a missed housekeeping task.
  - If the true uptime cannot be verified (no qualifying EventLog 6005 event and Fast Startup
    is enabled), say so as a data gap rather than assuming compliance or non-compliance.
- **Justify the finding with concrete mechanisms**, not just "best practice says so":
  accumulating handle/memory leaks in long-lived processes (cross-reference the top
  handle-holding process in section 14 - a growing count there over a long uptime is direct
  evidence, not a hypothetical), stale TCP/DNS state and port exhaustion (cross-reference
  section 10/25/35's Tcpip 4231/4266 warnings), and delayed application of any update that
  needs a restart to take effect (cross-reference sections 18/20's pending-reboot indicators
  and days-since-last-hotfix metric - an overdue restart directly explains an overdue patch).
- **Recommendation, if this rises to a finding**: the fix is procedural, not technical -
  scheduling a weekly (or policy-matching) restart, e.g. via a maintenance window, Group
  Policy, Task Scheduler, or an MDM/Intune compliance policy - rather than any registry or
  driver change. Do not suggest disabling Fast Startup as the fix for overdue restarts; that
  addresses measurement accuracy, not the underlying cadence problem.
- Place this finding in whichever severity band it earns based on the tiering above, and
  reflect the policy in the **Windows Update & Servicing** row of the Health Scorecard,
  since overdue restarts and unfinished servicing are directly linked here.

## 4b. Analysing the filter stacks (sections 32-35)

Filter drivers rarely announce themselves in the event log, so they must be assessed
structurally rather than by counting errors. Apply these rules:

- **Orphaned registrations.** A filter whose signer resolves to `FILE MISSING` is registered
  but has no binary. Treat as at least MEDIUM: it produces a failed load on every boot and
  proves an incomplete uninstall. Name the product it belonged to if you can infer it.
- **Anti-virus band collisions.** Two or more filters from *different vendors* in the
  320000-329999 band means two real-time scanners are inspecting every file operation.
  That is a HIGH finding for both performance and stability. One vendor registering several
  filters is normal and is not a collision.
- **Altitude/class mismatch.** A filter whose function does not match its declared band
  (e.g. a game anti-cheat or telemetry driver sitting in the Anti-Virus or Encryption band)
  is worth flagging - it inspects far more I/O than its purpose requires.
- **Unsigned or invalid-signature filters.** Any result of `UNSIGNED` or a non-`Valid`
  signature status on a kernel filter is CRITICAL. Say so plainly.
- **Stack depth.** Count the *running* minifilters. Roughly: up to ~14 is normal (more with containers/Hyper-V features) for a clean
  Windows 11 install; 13-20 is heavily layered; over 20 warrants a recommendation to
  consolidate. State the count and where this machine sits.
- **Legacy class filters (section 33).** UpperFilters/LowerFilters naming a driver with
  `NO SERVICE KEY` or `FILE MISSING` can prevent devices in that class from starting.
  Correlate directly with any Device Manager error codes in section 15 - a code 10 on a
  storage or USB device plus a dangling filter on that class is very likely one finding,
  not two.
- **NDIS bindings (section 34).** Flag any filter bound to an adapter it has no business
  touching, capture filters (`ms_ndiscap`) left enabled, and VPN filters still bound after
  the client was removed. Note when several vendors filter the same adapter.
- **WFP callouts.** Callouts from products not present in section 30's installed-software
  list indicate leftovers. Microsoft's own callouts (Defender, firewall, BFE, QoS) are
  expected and are not findings.
- **Winsock LSPs.** Any non-Microsoft provider path is significant - LSPs are a known
  adware and traffic-interception persistence mechanism. Report the full path.
- **Connect filters to symptoms.** Before calling a filter benign, check whether it explains
  something already observed: slow boot (section 13), file-operation latency, ephemeral port
  exhaustion (Tcpip 4231/4266 in sections 09/10), DNS failures, or application crashes.

**Never recommend removing or unloading a filter driver without first naming the product
that owns it and the supported uninstall path for that product.** Deleting a filter service
key directly can render a machine unbootable. `fltmc unload` is a diagnostic step, not a fix.

## 5. Constraints
- Be specific over comprehensive. A precise finding beats a generic checklist.
- Do not pad. If a domain is genuinely healthy, say so in one line and move on.
- Do not recommend third-party "cleaner", "optimiser" or "registry repair" utilities.
- Prefer built-in Windows tooling (DISM, SFC, CHKDSK, WinRE, Reliability Monitor,
  Event Viewer, Windows Update, vendor OEM firmware/driver tools) and name the exact command.
- Flag anything that looks like a hardware fault clearly and separately from software issues,
  because the remediation path (warranty/RMA) is completely different.
- If you see indicators of malware, tampering, or disabled security controls, escalate that
  to CRITICAL regardless of other findings.
- If the collected data shows no meaningful problems, say the machine is healthy. Do not
  manufacture findings to fill the template.
- Never end your response by asking for a complete or untruncated file instead of analysing.
  Work with what you were given and record the shortfall in Data Gaps.

=== BEGIN COLLECTED DATA ===
'@

$AiPrompt = $AiPrompt -replace '\$MaxUptimeDays', $MaxUptimeDays
Add-Line $AiPrompt
Add-Line ''
Add-Line "# Windows 11 Health Collection"
Add-Line ''
Add-Line "- **Computer:** $env:COMPUTERNAME"
Add-Line "- **Collected by:** $env:USERDOMAIN\$env:USERNAME"
Add-Line "- **Collected at:** $($StartTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
Add-Line "- **Event window:** $($Since.ToString('yyyy-MM-dd HH:mm')) to $($StartTime.ToString('yyyy-MM-dd HH:mm')) ($DaysBack day(s))"
Add-Line "- **Elevated collection:** $IsAdmin"
Add-Line "- **Collector version:** 2.5"
if ($env:HEALTHCHECK_LAUNCHER) { Add-Line "- **Launcher:** $env:HEALTHCHECK_LAUNCHER" }
Add-Line "- **Verbosity:** $Verbosity"
Add-Line "- **Expected restart cadence:** every $MaxUptimeDays day(s) (organisational policy; override with -MaxUptimeDays)"
Add-Line ''
Add-Line '<<<DIGEST>>>'
Add-Line ''

# ===========================================================================
# PART 2 - COLLECTION
# ===========================================================================
Write-Host "Collecting..." -ForegroundColor Yellow

# --- Inventory ---------------------------------------------------------------
Add-Section -Title '01. Operating System & Identity' -Purpose 'Confirms build/servicing state. Compare the build against the current supported Windows 11 release; an out-of-support build is itself a HIGH finding.' -Collector {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Caption          = $os.Caption
        DisplayVersion   = $cv.DisplayVersion
        BuildNumber      = "$($cv.CurrentBuild).$($cv.UBR)"
        Edition          = $cv.EditionID
        InstallDate      = $os.InstallDate
        LastBootUpTime   = $os.LastBootUpTime
        UptimeDays_WMI   = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
        FastStartupEnabled = $(try { [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled } catch { 'unknown' })
        Architecture     = $os.OSArchitecture
        Locale           = $os.Locale
        NOTE             = 'See "07. Crashes..." below for a Fast-Startup-aware reconciliation of LastBootUpTime/UptimeDays_WMI.'
        Domain           = $cs.Domain
        PartOfDomain     = $cs.PartOfDomain
        Manufacturer     = $cs.Manufacturer
        Model            = $cs.Model
        SystemType       = $cs.SystemType
        TotalRAM_GB      = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        LogicalProcessors= $cs.NumberOfLogicalProcessors
    } | Format-List
}

Add-Section -Title '02. Hardware Summary (CPU / Memory / GPU / Firmware)' -Purpose 'Establishes the hardware baseline. Old BIOS/UEFI dates and mismatched memory modules are common root causes of instability.' -Collector {
    "=== CPU ==="
    Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors,
        MaxClockSpeed, CurrentClockSpeed, L2CacheSize, L3CacheSize, Status | Format-List
    "=== BIOS / UEFI ==="
    Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, SMBIOSBIOSVersion, ReleaseDate, SerialNumber | Format-List
    "=== Baseboard ==="
    Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, Version | Format-List
    "=== Physical Memory Modules ==="
    Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel, DeviceLocator,
        @{n='Capacity_GB';e={[math]::Round($_.Capacity/1GB,2)}}, Speed, ConfiguredClockSpeed,
        Manufacturer, PartNumber, SerialNumber | Format-Table -AutoSize
    "=== Graphics ==="
    Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate,
        @{n='VRAM_GB';e={[math]::Round($_.AdapterRAM/1GB,2)}}, CurrentHorizontalResolution,
        CurrentVerticalResolution, CurrentRefreshRate, Status | Format-List
}

# --- Storage -----------------------------------------------------------------
Add-Section -Title '03. Volumes & Free Space' -Purpose 'Under ~15% free on the system volume degrades update installation, paging and defrag. Under 10% is a HIGH finding.' -Collector {
    Get-Volume | Where-Object DriveLetter | Sort-Object DriveLetter |
        Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, OperationalStatus,
            @{n='Size_GB';e={[math]::Round($_.Size/1GB,2)}},
            @{n='Free_GB';e={[math]::Round($_.SizeRemaining/1GB,2)}},
            @{n='PctFree';e={ if($_.Size){[math]::Round(($_.SizeRemaining/$_.Size)*100,1)} else {0} }} |
        Format-Table -AutoSize
}

Add-Section -Title '04. Physical Disk Health & SMART Reliability Counters' -Purpose 'Any non-zero ReadErrorsUncorrected, ReallocatedSectors, or Wear above ~80% on an SSD is a CRITICAL hardware finding requiring backup and replacement, not software remediation.' -Collector {
    "=== Physical Disks ==="
    Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, BusType, HealthStatus,
        OperationalStatus, @{n='Size_GB';e={[math]::Round($_.Size/1GB,2)}}, FirmwareVersion, SerialNumber |
        Format-Table -AutoSize
    "`n=== Reliability Counters ==="
    Get-PhysicalDisk | ForEach-Object {
        $d = $_
        try {
            $c = $d | Get-StorageReliabilityCounter -ErrorAction Stop
            [PSCustomObject]@{
                Disk                   = $d.FriendlyName
                Temperature_C          = $c.Temperature
                MaxTemperature_C       = $c.TemperatureMax
                PowerOnHours           = $c.PowerOnHours
                StartStopCycles        = $c.StartStopCycleCount
                Wear_Pct               = $c.Wear
                ReadErrorsCorrected    = $c.ReadErrorsCorrected
                ReadErrorsUncorrected  = $c.ReadErrorsUncorrected
                WriteErrorsCorrected   = $c.WriteErrorsCorrected
                WriteErrorsUncorrected = $c.WriteErrorsUncorrected
            }
        } catch {
            [PSCustomObject]@{ Disk = $d.FriendlyName; Temperature_C = "unavailable: $($_.Exception.Message)" }
        }
    } | Format-List
    "`n=== Disk Drive WMI Status ==="
    Get-CimInstance Win32_DiskDrive | Select-Object Model, InterfaceType, Status, Partitions,
        @{n='Size_GB';e={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize
}

Add-Section -Title '05. Storage & Filesystem Error Events' -Purpose 'Providers disk/Ntfs/volmgr/storahci with IDs 7, 51, 55, 98, 129, 153, 157 indicate controller timeouts, corruption or failing media. Correlate with section 04.' -Collector {
    $ev = Get-EventsSafe -LogName 'System' -ProviderName @('disk','Disk','Ntfs','volmgr','volsnap','storahci','stornvme','partmgr','Microsoft-Windows-Ntfs','Microsoft-Windows-DiskDiagnostic','Microsoft-Windows-DiskDiagnosticDataCollector')
    Format-EventReport -Events $ev
}

Add-Section -Title '06. Memory Diagnostic Results' -Purpose 'If no results exist, recommend running mdsched.exe when RAM-related bugchecks are suspected.' -Collector {
    $ev = Get-EventsSafe -LogName 'System' -ProviderName 'Microsoft-Windows-MemoryDiagnostics-Results' -Days 365
    if ($ev.Count -eq 0) { 'No Windows Memory Diagnostic has been run recently (no results in the last 365 days).' }
    else { $ev | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, @{n='Message';e={Get-ShortText $_.Message 300}} | Format-List }
}

# --- Stability ---------------------------------------------------------------
Add-Section -Title '07. Crashes, Bugchecks & Unexpected Shutdowns' -Purpose 'Kernel-Power ID 41 = power loss or hard hang. BugCheck ID 1001 carries the stop code. EventLog ID 6008 = dirty shutdown. A recurring pattern here is the single strongest stability signal. IMPORTANT: read the Boot/Uptime Accuracy Cross-Check first - if Fast Startup is enabled, Win32_OperatingSystem.LastBootUpTime does NOT reflect the true time of the last power-on, so any uptime-based reasoning elsewhere in this report must defer to the reconciled figure here.' -Collector {
    "=== Boot/Uptime Accuracy Cross-Check (Fast Startup) ==="
    $hiber = try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled } catch { $null }
    $wmiBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $evtLog6005 = Get-EventsSafe -LogName 'System' -Id 6005 -Days 90 -Max 200
    $lastEvtLog = $evtLog6005 | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $powerOnSource = 'Event 6005'
    # Fallback: the System log often wraps within days on busy machines (see section 29), so 6005 may be gone.
    # Diagnostics-Performance ID 100 (boot performance) is in a separate, rarely-flooded log and is also written on every boot.
    $d100 = @(Get-EventsSafe -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -Id 100 -Days 90 -Max 200)
    if (-not $lastEvtLog -and $d100.Count) {
        $lastEvtLog = $d100 | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $powerOnSource = 'Diagnostics-Performance ID 100 (6005 had wrapped out of the System log)'
    }
    $oldestSys = try { (Get-WinEvent -LogName System -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { $null }
    "System log oldest record        : $(if ($oldestSys) { $oldestSys } else { 'n/a' })  (anything older than this cannot be evidenced)"

    "Fast Startup (HiberbootEnabled) : $(if ($null -eq $hiber) {'registry value not present (treat as unknown, not disabled)'} elseif ($hiber -eq 1) {'ENABLED'} else {'Disabled'})"
    "WMI LastBootUpTime (tick-based) : $wmiBoot"
    "Most recent true power-on marker : $(if ($lastEvtLog) { "$($lastEvtLog.TimeCreated)  [source: $powerOnSource]" } else { 'none found in the last 90 days (6005 and Diagnostics-Performance ID 100 both absent)' })"

    if ($lastEvtLog) {
        $gapHours = [math]::Round((New-TimeSpan -Start $wmiBoot -End $lastEvtLog.TimeCreated).TotalHours, 1)
        "Discrepancy : $gapHours hours"
        if ($hiber -eq 1 -and $gapHours -gt 1) {
            "`nASSESSMENT: Fast Startup is enabled and the two timestamps disagree by more than an hour."
            "This is EXPECTED behaviour, not a fault. Fast Startup hibernates the kernel session on"
            "shutdown rather than terminating it, so WMI's tick-based uptime counter survives the power"
            "cycle and keeps counting from the last true cold boot ($wmiBoot). Event ID 6005 fires fresh"
            "on every power-on because the Event Log service genuinely restarts in the new user session,"
            "so its timestamp ($($lastEvtLog.TimeCreated)) is the more accurate 'last power-on' figure."
            "`nUse the EventLog-based figure, not UptimeDays_WMI in section 01, when reasoning about how"
            "recently this machine was actually restarted."
        }
        elseif ($gapHours -le 1) {
            "`nASSESSMENT: the two sources agree (within an hour). LastBootUpTime is reliable here -"
            "either Fast Startup is off, or the machine has not been power-cycled since the last cold boot."
        }
    }
    else {
        "`nASSESSMENT: no EventLog service start events found in the last 90 days to cross-check against."
        "If Fast Startup is enabled, treat UptimeDays_WMI in section 01 with caution regardless."
    }

    "`n--- Power-on history (6005, else Diagnostics-Performance ID 100; last 90 days) ---"
    $hist = @(if ($evtLog6005.Count) { $evtLog6005 } else { $d100 }) | Sort-Object TimeCreated -Descending
    if ($hist.Count) {
        $hist | Select-Object -First 20 TimeCreated | Format-Table -AutoSize
        $asc = @($hist | Sort-Object TimeCreated | ForEach-Object { $_.TimeCreated })
        $maxGap = 0.0
        for ($i = 1; $i -lt $asc.Count; $i++) { $g = ($asc[$i] - $asc[$i-1]).TotalDays; if ($g -gt $maxGap) { $maxGap = $g } }
        "Longest observed gap between power-ons : $([math]::Round($maxGap,1)) day(s)  (a lower bound - wrapped logs hide earlier gaps)"
    } else { 'None recorded.' }

    "`n=== Restart Cadence Policy Check ==="
    "Policy: restart at least every $MaxUptimeDays day(s) (organisational expectation, set via -MaxUptimeDays)."
    if ($lastEvtLog) {
        $trueUptimeDays = [math]::Round(((Get-Date) - $lastEvtLog.TimeCreated).TotalDays, 1)
        "True uptime since last power-on : $trueUptimeDays day(s)"
        if ($trueUptimeDays -le $MaxUptimeDays) {
            "Status: WITHIN POLICY."
        } else {
            $mult = [math]::Round($trueUptimeDays / $MaxUptimeDays, 1)
            "Status: OVERDUE by $([math]::Round($trueUptimeDays - $MaxUptimeDays, 1)) day(s) - ${mult}x the policy interval."
            "Extended uptime allows in-memory leaks (see the top-handle-holder check in section 14),"
            "abandoned TCP state and stale DNS/network state to accumulate, and delays application of"
            "any update that requires a restart to take effect (cross-reference section 18/20)."
        }
    } else {
        "True uptime cannot be verified (no EventLog 6005 event in the last 90 days). If Fast Startup"
        "is enabled, do not treat WMI's LastBootUpTime as evidence of compliance either way."
    }

    "`n=== Kernel-Power 41 (unexpected power loss / hang) ==="
    $k = Get-EventsSafe -LogName 'System' -Id 41 -ProviderName 'Microsoft-Windows-Kernel-Power' -Days 90
    if ($k.Count) { $k | Sort-Object TimeCreated -Descending | Select-Object -First 20 TimeCreated, Id, @{n='Detail';e={Get-ShortText $_.Message 300}} | Format-List }
    else { 'None in the last 90 days.' }

    "`n=== BugCheck (Blue Screen) 1001 ==="
    $b = Get-EventsSafe -LogName 'System' -Id 1001 -ProviderName 'Microsoft-Windows-WER-SystemErrorReporting' -Days 90
    if ($b.Count) { $b | Sort-Object TimeCreated -Descending | Select-Object -First 20 TimeCreated, @{n='StopInfo';e={Get-ShortText $_.Message 400}} | Format-List }
    else { 'No bugcheck records in the last 90 days.' }

    "`n=== Dirty / Unexpected Shutdowns (EventLog 6008) ==="
    $s = Get-EventsSafe -LogName 'System' -Id 6008 -Days 90
    if ($s.Count) { $s | Sort-Object TimeCreated -Descending | Select-Object -First 20 TimeCreated, @{n='Detail';e={Get-ShortText $_.Message 200}} | Format-List }
    else { 'None in the last 90 days.' }

    "`n=== Shutdown / Restart Reasons (1074, 1076, 6005, 6006, 6013) ==="
    $r = Get-EventsSafe -LogName 'System' -Id @(1074,1076,6005,6006) -Days 30
    if ($r.Count) { $r | Sort-Object TimeCreated -Descending | Select-Object -First 25 TimeCreated, Id, @{n='Detail';e={Get-ShortText $_.Message 250}} | Format-List }
    else { 'No records.' }

    "`n=== Crash Dump Files Present ==="
    $dumps = @()
    $dumps += Get-ChildItem "$env:SystemRoot\MEMORY.DMP" -ErrorAction SilentlyContinue
    $dumps += Get-ChildItem "$env:SystemRoot\Minidump\*.dmp" -ErrorAction SilentlyContinue
    $dumps += Get-ChildItem "$env:LOCALAPPDATA\CrashDumps\*.dmp" -ErrorAction SilentlyContinue
    if ($dumps) { $dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 25 FullName, LastWriteTime, @{n='Size_MB';e={[math]::Round($_.Length/1MB,2)}} | Format-Table -AutoSize }
    else { 'No crash dump files found.' }

    "`n=== Dump Configuration ==="
    Get-CimInstance Win32_OSRecoveryConfiguration | Select-Object DebugInfoType, DebugFilePath,
        MiniDumpDirectory, AutoReboot, OverwriteExistingDebugFile | Format-List
}

Add-Section -Title '08. Application Crashes & Hangs (WER)' -Purpose 'Application Error 1000 / Application Hang 1002 / .NET Runtime 1026. Repeated faults in the same faulting module across different apps often point to a shared driver, codec or security product.' -Collector {
    $ev = Get-EventsSafe -LogName 'Application' -Id @(1000,1001,1002,1026) -ProviderName @('Application Error','Application Hang','.NET Runtime','Windows Error Reporting')
    Format-EventReport -Events $ev
}

Add-Section -Title '09. System Log - Critical & Error' -Purpose 'The primary stability feed. Use the frequency table to separate chronic noise from acute faults.' -Collector {
    $ev = Get-EventsSafe -LogName 'System' -Level @(1,2)
    Format-EventReport -Events $ev
}

Add-Section -Title '10. System Log - Warnings' -Purpose 'Often the early-warning tier: disk timeouts, DNS failures and driver resets appear here before they escalate to errors.' -Collector {
    $ev = Get-EventsSafe -LogName 'System' -Level @(3)
    Format-EventReport -Events $ev -DetailCount ([math]::Min($DetailEventCount,15))
}

Add-Section -Title '11. Application Log - Critical & Error' -Purpose 'Application-tier faults. Cross-reference with section 08.' -Collector {
    $ev = Get-EventsSafe -LogName 'Application' -Level @(1,2)
    Format-EventReport -Events $ev
}

Add-Section -Title '12. Reliability Monitor History' -Purpose 'Win32_ReliabilityRecords is the same data behind perfmon /rel. Useful for spotting a stability inflection point tied to a specific install date.' -Collector {
    try {
        $rr = Get-CimInstance Win32_ReliabilityRecords -ErrorAction Stop |
              Where-Object { $_.TimeGenerated -ge $Since } |
              Sort-Object TimeGenerated -Descending
        if (-not $rr) { 'No reliability records in the window.' }
        else {
            "Total records: $($rr.Count)"
            "`n--- Grouped by source ---"
            $rr | Group-Object SourceName | Sort-Object Count -Descending | Select-Object -First 20 Count, Name | Format-Table -AutoSize
            "`n--- Most recent $DetailEventCount ---"
            $rr | Select-Object -First $DetailEventCount TimeGenerated, SourceName, EventIdentifier,
                @{n='Message';e={Get-ShortText $_.Message 250}} | Format-List
        }
    } catch { "Reliability records unavailable: $($_.Exception.Message)" }
}

# --- Boot / performance ------------------------------------------------------
Add-Section -Title '13. Boot & Shutdown Performance' -Purpose 'Diagnostics-Performance IDs: 100 boot, 200 shutdown, 101/102 degradation by app/driver, 103 service delay, 109 device delay, 110 disk delay. BootTime over ~60s warrants investigation.' -Collector {
    $ev = Get-EventsSafe -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -Days ([math]::Max($DaysBack,30))
    if (-not $ev.Count) { 'No boot performance events (log may be disabled).'; return }
    "=== Boot summary (ID 100) ==="
    $ev | Where-Object Id -eq 100 | Sort-Object TimeCreated -Descending | Select-Object -First 15 `
        TimeCreated, @{n='Detail';e={Get-ShortText $_.Message 300}} | Format-List
    "`n=== Degradation contributors (101/102/103/106/109/110) ==="
    $ev | Where-Object { $_.Id -in 101,102,103,106,109,110 } | Sort-Object TimeCreated -Descending |
        Select-Object -First 30 TimeCreated, Id, @{n='Detail';e={Get-ShortText $_.Message 250}} | Format-List
    "`n=== Shutdown (ID 200/201/202/203) ==="
    $ev | Where-Object { $_.Id -in 200,201,202,203 } | Sort-Object TimeCreated -Descending |
        Select-Object -First 10 TimeCreated, Id, @{n='Detail';e={Get-ShortText $_.Message 250}} | Format-List
}

Add-Section -Title '14. Live Performance Snapshot' -Purpose 'A point-in-time sample only. Do not draw firm conclusions from a single sample; use it to corroborate log-based findings.' -Collector {
    $os = Get-CimInstance Win32_OperatingSystem
    "=== Memory ==="
    [PSCustomObject]@{
        TotalVisible_GB = [math]::Round($os.TotalVisibleMemorySize/1MB,2)
        FreePhysical_GB = [math]::Round($os.FreePhysicalMemory/1MB,2)
        PctUsed         = [math]::Round((1 - ($os.FreePhysicalMemory/$os.TotalVisibleMemorySize))*100,1)
        CommitLimit_GB  = [math]::Round($os.TotalVirtualMemorySize/1MB,2)
        CommitFree_GB   = [math]::Round($os.FreeVirtualMemory/1MB,2)
    } | Format-List

    "=== Page File ==="
    Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue |
        Select-Object Name, AllocatedBaseSize, CurrentUsage, PeakUsage | Format-Table -AutoSize

    "=== CPU Load (5 x 1s samples) ==="
    try {
        (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 5 -ErrorAction Stop).CounterSamples |
            Select-Object Timestamp, @{n='CPU_Pct';e={[math]::Round($_.CookedValue,1)}} | Format-Table -AutoSize
    } catch { "Counter unavailable: $($_.Exception.Message)" }

    "=== Top 15 processes by working set ==="
    Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 `
        Name, Id, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}},
        @{n='CPU_s';e={[math]::Round($_.CPU,1)}}, Handles, StartTime | Format-Table -AutoSize

    "=== Top 15 processes by CPU time ==="
    Get-Process | Where-Object CPU | Sort-Object CPU -Descending | Select-Object -First 15 `
        Name, Id, @{n='CPU_s';e={[math]::Round($_.CPU,1)}},
        @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}} | Format-Table -AutoSize

    "=== Top handle-holding process, with hosted services ==="
    $topH = Get-Process | Sort-Object Handles -Descending | Select-Object -First 1
    "Process: $($topH.Name)  PID: $($topH.Id)  Handles: $($topH.Handles)  Started: $($topH.StartTime)"
    if ($topH.Name -eq 'svchost') {
        Get-CimInstance Win32_Service -Filter "ProcessId=$($topH.Id)" -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State | Format-Table -AutoSize -Wrap
    }

    "=== Handle / thread totals ==="
    [PSCustomObject]@{
        ProcessCount = (Get-Process).Count
        TotalHandles = ((Get-Process | Measure-Object Handles -Sum).Sum)
        TotalThreads = (Get-Process | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum
    } | Format-List
}

# --- Devices / drivers -------------------------------------------------------
Add-Section -Title '15. Problem Devices' -Purpose 'ConfigManagerErrorCode <> 0 means the device is not working. Code 28 = no driver, 43 = device reported failure, 10 = cannot start. Any entry here is at least a MEDIUM finding.' -Collector {
    $bad = Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
    if (-not $bad) { 'No devices reporting a Device Manager error code.' }
    else {
        $bad | Select-Object Name, DeviceID, ConfigManagerErrorCode, Status, Manufacturer |
            Format-Table -AutoSize -Wrap
    }
}

Add-Section -Title '16. Third-Party Drivers (age & version)' -Purpose 'Drivers older than ~3 years, or newer than the onset of instability, are prime suspects. Match against bugcheck faulting modules in section 07.' -Collector {
    Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.DeviceName -and $_.DriverProviderName -and $_.DriverProviderName -notmatch 'Microsoft' } |
        Sort-Object DriverDate | Select-Object -First $script:TableCap |
        Select-Object DeviceName, DriverProviderName, DriverVersion,
            @{n='DriverDate';e={ if($_.DriverDate){([datetime]$_.DriverDate).ToString('yyyy-MM-dd')} }}, IsSigned |
        Format-Table -AutoSize -Wrap
}

Add-Section -Title '17. Driver / Kernel Load Events' -Purpose 'Driver resets (nvlddmkm/amdkmdag TDR), Kernel-PnP 219 load failures and Service Control Manager driver start failures live here.' -Collector {
    $ev = Get-EventsSafe -LogName 'System' -ProviderName @('Microsoft-Windows-Kernel-PnP','Microsoft-Windows-DriverFrameworks-UserMode','Display','nvlddmkm','amdkmdag','igfxn') -Level @(1,2,3)
    Format-EventReport -Events $ev -DetailCount 15
}

# --- Servicing ---------------------------------------------------------------
Add-Section -Title '18. Windows Update - Installed Hotfixes' -Purpose 'A gap of more than ~45 days since the last quality update is a HIGH security finding.' -Collector {
    $hf = Get-HotFix -ErrorAction SilentlyContinue |
        Select-Object HotFixID, Description, InstalledBy,
            @{n='InstalledOn'; e={ try { [datetime]$_.InstalledOn } catch { $null } }}
    $hf | Sort-Object @{e={ if ($_.InstalledOn) { $_.InstalledOn } else { [datetime]::MinValue } }} -Descending |
        Select-Object -First 40 HotFixID, Description,
            @{n='InstalledOn'; e={ if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { 'PENDING / no date' } }},
            InstalledBy | Format-Table -AutoSize
    $latest = ($hf | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1)
    "`nMost recent dated update : $(if ($latest) { $latest.HotFixID + ' on ' + $latest.InstalledOn.ToString('yyyy-MM-dd') } else { 'none' })"
    "Days since that update   : $(if ($latest) { [math]::Round(((Get-Date) - $latest.InstalledOn).TotalDays, 1) } else { 'n/a' })"
    "Undated entries (staged) : $(@($hf | Where-Object { -not $_.InstalledOn }).Count)"
}

Add-Section -Title '19. Windows Update - Client Activity & Failures' -Purpose 'Repeated failure of the same KB indicates a servicing-stack or component-store problem; recommend DISM /RestoreHealth before any reset.' -Collector {
    $ev = Get-EventsSafe -LogName 'System' -ProviderName 'Microsoft-Windows-WindowsUpdateClient' -Days ([math]::Max($DaysBack,30))
    Format-EventReport -Events $ev -DetailCount 20
    "`n=== Setup log (servicing) errors ==="
    $s = Get-EventsSafe -LogName 'Setup' -Level @(1,2,3) -Days ([math]::Max($DaysBack,60))
    Format-EventReport -Events $s -DetailCount 15
}

Add-Section -Title '20. Pending Reboot Indicators' -Purpose 'A long-outstanding pending reboot blocks servicing and is a common cause of "updates keep failing".' -Collector {
    $checks = [ordered]@{
        'CBS RebootPending'        = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        'WU RebootRequired'        = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        'PendingFileRenameOps'     = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
        'ComputerRenamePending'    = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName -ne
                                      (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName)
    }
    $checks.GetEnumerator() | Select-Object @{n='Indicator';e={$_.Key}}, @{n='Pending';e={$_.Value}} | Format-Table -AutoSize
}

# --- Services / tasks --------------------------------------------------------
Add-Section -Title '21. Services - Automatic but Not Running' -Purpose 'Some entries are benign (trigger-start services). Judge by service identity, not count alone.' -Collector {
    Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } |
        Select-Object Name, DisplayName, State, StartMode, StartName, ExitCode | Format-Table -AutoSize -Wrap
}

Add-Section -Title '22. Service Control Manager Failures' -Purpose 'IDs 7000/7001/7009/7011/7023/7024/7031/7034 = start failure, timeout, unexpected termination or dependency failure.' -Collector {
    $ev = Get-EventsSafe -LogName 'System' -ProviderName 'Service Control Manager' -Level @(1,2,3)
    Format-EventReport -Events $ev -DetailCount 20
}

Add-Section -Title '23. Scheduled Tasks - Non-Zero Last Result' -Purpose 'Failing maintenance tasks (defrag, restore point, telemetry, backup) silently erode health over time.' -Collector {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object State -ne 'Disabled' |
        ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            if ($info -and $info.LastTaskResult -ne 0 -and $null -ne $info.LastRunTime) {
                [PSCustomObject]@{
                    TaskPath   = $_.TaskPath
                    TaskName   = $_.TaskName
                    State      = $_.State
                    LastRun    = $info.LastRunTime
                    LastResult = ('0x{0:X8}' -f $info.LastTaskResult)
                    NextRun    = $info.NextRunTime
                }
            }
        } | Sort-Object LastRun -Descending | Select-Object -First $script:TableCap | Format-Table -AutoSize -Wrap
}

Add-Section -Title '24. Startup Programs' -Purpose 'Correlate with boot-degradation events in section 13 before recommending any removal.' -Collector {
    Get-CimInstance Win32_StartupCommand | Select-Object -First $script:TableCap Name, Command, Location, User |
        Format-Table -AutoSize -Wrap
}

# --- Network -----------------------------------------------------------------
Add-Section -Title '25. Network Configuration & Connectivity' -Purpose 'Check for APIPA addresses, missing gateways, duplicate DNS suffixes and adapters in a disconnected/error state.' -Collector {
    "=== Adapters ==="
    Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status,
        LinkSpeed, MacAddress, MediaConnectionState, DriverVersion, DriverDate | Format-Table -AutoSize -Wrap
    "`n=== IP Configuration ==="
    Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Alias   = $_.InterfaceAlias
            IPv4    = ($_.IPv4Address.IPAddress -join ', ')
            IPv6    = ($_.IPv6Address.IPAddress -join ', ')
            Gateway = ($_.IPv4DefaultGateway.NextHop -join ', ')
            DNS     = ($_.DNSServer | Where-Object AddressFamily -eq 2 |
                       ForEach-Object { $_.ServerAddresses }) -join ', '
        }
    } | Format-Table -AutoSize -Wrap
    "`n=== TCP connection summary by state ==="
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Group-Object State |
        Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
    "`n=== Connectivity tests ==="
    foreach ($t in @('8.8.8.8','1.1.1.1')) {
        $r = Test-Connection -ComputerName $t -Count 3 -Quiet -ErrorAction SilentlyContinue
        "Ping $t : $(if($r){'SUCCESS'}else{'FAILED'})"
    }
    try {
        $tnc = Test-NetConnection -ComputerName 'www.microsoft.com' -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue
        "TCP 443 to www.microsoft.com : $($tnc.TcpTestSucceeded)  (resolved: $($tnc.RemoteAddress))"
    } catch { "TCP test failed: $($_.Exception.Message)" }
    "`n=== Network-related error events ==="
    $ev = Get-EventsSafe -LogName 'System' -ProviderName @('Microsoft-Windows-DNS-Client','Microsoft-Windows-Dhcp-Client','Microsoft-Windows-NlaSvc','Tcpip','e1dexpress','Netwtw10') -Level @(1,2,3)
    Format-EventReport -Events $ev -DetailCount 10
}

# --- Security ----------------------------------------------------------------
Add-Section -Title '26. Security Posture' -Purpose 'Disabled real-time protection, stale signatures, unencrypted volumes, disabled Secure Boot or an unready TPM are each at least HIGH findings. Defender exclusions: broad ones (a whole drive, the user profile, system folders, or file types like .exe/.dll) are a security concern; exclusions for OUTLOOK.EXE or .ost/.pst files are normal, deliberate performance tuning and are not a finding.' -Collector {
    "=== Microsoft Defender status ==="
    try {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, AntivirusEnabled,
            RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, TamperProtectionSource,
            AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge,
            NISEnabled, IsTamperProtected | Format-List
    } catch { "Defender status unavailable: $($_.Exception.Message)" }

    "`n=== Microsoft Defender exclusions (needs Administrator to read) ==="
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $exPath = @($pref.ExclusionPath | Where-Object { $_ }); $exExt = @($pref.ExclusionExtension | Where-Object { $_ }); $exProc = @($pref.ExclusionProcess | Where-Object { $_ })
        if (($exPath + $exExt + $exProc) -match '^N/A') { 'Exclusions are hidden from a non-elevated session. Re-run as Administrator to read them.' }
        else {
            "Excluded paths ($($exPath.Count)):";      $exPath | Select-Object -First 40 | ForEach-Object { "  $_" }
            "Excluded extensions ($($exExt.Count)):"; $exExt  | Select-Object -First 40 | ForEach-Object { "  $_" }
            "Excluded processes ($($exProc.Count)):"; $exProc | Select-Object -First 40 | ForEach-Object { "  $_" }
            $broad = @($exPath | Where-Object { $_ -match '^[A-Za-z]:\\?\*?$' -or $_ -match '^[A-Za-z]:\\(Users|Windows|Program Files( \(x86\))?)\\?\*?$' })
            "`n--- Assessment aids ---"
            "Broad exclusions (whole drive, user profile or system folders) : $($broad.Count)$(if ($broad.Count) { '  -> ' + ($broad -join '; ') })"
            "OUTLOOK.EXE process excluded                                    : $([bool]($exProc | Where-Object { $_ -match '(^|\\)outlook\.exe$' }))"
            "Outlook data excluded (.ost/.pst extension or an Outlook path)  : $([bool](($exExt | Where-Object { $_ -match '^\.?(ost|pst)$' }) -or ($exPath | Where-Object { $_ -match 'Outlook' })))"
        }
    } catch { "Defender exclusions unavailable (a third-party antivirus may be the active engine): $($_.Exception.Message)" }

    "`n=== Registered security products ==="
    try {
        Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            Select-Object displayName, productState, timestamp | Format-Table -AutoSize
    } catch { "SecurityCenter2 unavailable: $($_.Exception.Message)" }

    "`n=== Recent threat detections ==="
    try {
        $t = Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 25
        if ($t) { $t | Select-Object InitialDetectionTime, ThreatID, ActionSuccess, ThreatStatusID, Resources | Format-List }
        else { 'No threat detections recorded.' }
    } catch { "Threat history unavailable: $($_.Exception.Message)" }

    "`n=== Firewall profiles ==="
    try { Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize }
    catch { "Firewall query failed: $($_.Exception.Message)" }

    "`n=== BitLocker ==="
    try { Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod, KeyProtector | Format-Table -AutoSize -Wrap }
    catch { "BitLocker query failed (requires elevation / supported edition): $($_.Exception.Message)" }

    "`n=== Secure Boot ==="
    try { "SecureBootEnabled: $(Confirm-SecureBootUEFI -ErrorAction Stop)" }
    catch { "Secure Boot state unavailable (legacy BIOS or insufficient rights): $($_.Exception.Message)" }

    "`n=== TPM ==="
    try { Get-Tpm -ErrorAction Stop | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManagedAuthLevel, LockedOut | Format-List }
    catch { "TPM query failed: $($_.Exception.Message)" }

    "`n=== Local administrators ==="
    try { Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize }
    catch { "Local group query failed: $($_.Exception.Message)" }
}

Add-Section -Title '27. Security & Audit Log Highlights' -Purpose 'Look for repeated 4625 failed logons, 1102 log clears, and 4720/4732 account changes. Requires elevation.' -Collector {
    if (-not $IsAdmin) { 'Skipped - requires elevation.'; return }
    $ev = Get-EventsSafe -LogName 'Security' -Id @(1102,4625,4720,4726,4732,4740) -Max 1000
    Format-EventReport -Events $ev -DetailCount 10
}

# --- Config hygiene ----------------------------------------------------------
Add-Section -Title '28. Power Configuration' -Purpose 'Check for aggressive sleep/hibernate settings that correlate with Kernel-Power events, and for fast startup masking clean-boot behaviour.' -Collector {
    powercfg /list
    "`n=== Active scheme detail (subset) ==="
    powercfg /query SCHEME_CURRENT SUB_SLEEP
    "`n=== Sleep availability ==="
    powercfg /availablesleepstates
    "`n=== Devices allowed to wake the machine ==="
    powercfg /devicequery wake_armed
    "`n=== Last wake source ==="
    powercfg /lastwake
}

Add-Section -Title '29. Event Log Health & Retention' -Purpose 'A log that is full or wrapping in hours means evidence is being lost; recommend increasing MaxSize before further diagnosis.' -Collector {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordCount -gt 0 } | Sort-Object RecordCount -Descending | Select-Object -First $script:TableCap `
        LogName, IsEnabled, LogMode, RecordCount,
        @{n='MaxSize_MB';e={[math]::Round($_.MaximumSizeInBytes/1MB,1)}},
        @{n='Current_MB';e={[math]::Round($_.FileSize/1MB,1)}},
        @{n='OldestRecord';e={ try {(Get-WinEvent -LogName $_.LogName -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated} catch {'n/a'} }} |
        Format-Table -AutoSize

    "`n=== Top event sources by volume in the System log (what is filling it) ==="
    try {
        Get-WinEvent -LogName System -MaxEvents 20000 -ErrorAction Stop | Group-Object ProviderName |
            Sort-Object Count -Descending | Select-Object -First 8 Count, Name | Format-Table -AutoSize
        "(based on the newest 20,000 System events; a single source dominating this list is the log flood to investigate)"
        "`n--- Top provider / event ID pairs, with a sample message from the busiest ---"
        $pairs = @(Get-WinEvent -LogName System -MaxEvents 20000 -ErrorAction Stop | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 5)
        $pairs | Select-Object Count, Name | Format-Table -AutoSize
        if ($pairs.Count) {
            $top = $pairs[0].Group
            "Busiest pair first seen $((($top | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated)), last seen $((($top | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated))"
            "Sample: " + (Get-ShortText $top[0].Message 400)
        }
    } catch { 'Could not sample the System log.' }
}

Add-Section -Title '30. Recently Installed Software' -Purpose 'Correlate install dates against the onset of instability identified in sections 07-12.' -Collector {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    "Total installed applications detected: $(@($apps).Count)"
    "`n--- 30 most recent by InstallDate ---"
    $apps | Where-Object InstallDate | Sort-Object InstallDate -Descending | Select-Object -First $script:TableCap |
        Format-Table -AutoSize -Wrap
}

Add-Section -Title '31. System Restore & Recovery Readiness' -Purpose 'No restore points and no recovery partition materially raises the risk of every remediation recommended below. Flag this if remediation is invasive.' -Collector {
    "=== Restore points ==="
    try {
        $rp = Get-ComputerRestorePoint -ErrorAction Stop
        if ($rp) { $rp | Select-Object CreationTime, Description, RestorePointType, SequenceNumber | Format-Table -AutoSize }
        else { 'No restore points found.' }
    } catch { "Restore point query failed (System Protection may be off): $($_.Exception.Message)" }
    "`n=== Windows RE status ==="
    reagentc /info
    "`n=== Shadow copy storage ==="
    vssadmin list shadowstorage 2>&1
}

# --- Filter stacks ------------------------------------------------------------
Add-Section -Title '32. File System Filter Drivers (minifilters)' -Purpose 'Every file I/O on this machine passes through this stack in altitude order (highest first). Look for: orphaned registrations whose driver file is MISSING; two or more filters in the ANTI-VIRUS band (320000-329999) from different vendors; unsigned or non-Microsoft filters at unusually high altitude; and filters belonging to software that was uninstalled. Each active filter adds latency to every open, read, write and close.' -Collector {
    "=== fltmc filters (currently loaded) ==="
    if ($IsAdmin) { fltmc.exe filters } else { 'Skipped - fltmc requires elevation.' }

    "`n=== fltmc instances (per-volume attachments) ==="
    if (-not $IsAdmin) { 'Skipped - fltmc requires elevation.' }
    elseif ($Verbosity -eq 'Compact') { '(omitted in Compact mode; see the registry table below)' }
    else { fltmc.exe instances | Select-Object -First 120 }

    "`n=== Registered minifilters from the registry, with altitude classification ==="
    $running = @{}
    Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        ForEach-Object { $running[$_.Name] = $_.State }

    $mf = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $svcKey  = $_
            $svc     = Get-ItemProperty $svcKey.PSPath -ErrorAction SilentlyContinue
            $instRoot = Join-Path $svcKey.PSPath 'Instances'
            if (Test-Path $instRoot) {
                Get-ChildItem $instRoot -ErrorAction SilentlyContinue | ForEach-Object {
                    $inst = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    if ($inst.Altitude) {
                        [PSCustomObject]@{
                            Altitude = $inst.Altitude
                            Class    = Get-FilterAltitudeClass $inst.Altitude
                            Service  = $svcKey.PSChildName
                            State    = $(if ($running.ContainsKey($svcKey.PSChildName)) { $running[$svcKey.PSChildName] } else { 'not loaded' })
                            StartVal = $svc.Start
                            Signer   = Get-DriverSigner $svc.ImagePath $svcKey.PSChildName
                            Image    = $svc.ImagePath
                        }
                    }
                }
            }
        }
    $mf | Sort-Object { [double]$_.Altitude } -Descending |
        Select-Object -First ([math]::Max($script:TableCap, 30)) |
        Format-Table -AutoSize -Wrap Altitude, Class, Service, State, StartVal, Signer

    "`n=== Summary ==="
    "Total registered minifilter instances : $(@($mf).Count)"
    "Currently running                     : $(@($mf | Where-Object State -eq 'Running').Count)"
    "Orphaned (driver file missing)        : $(@($mf | Where-Object Signer -eq 'FILE MISSING').Count)"
    "Non-Microsoft signers                 : $(@($mf | Where-Object { $_.Signer -notmatch 'Microsoft|^no ImagePath|^signature check failed' -and $_.Signer -ne 'FILE MISSING' }).Count)"
    "`n--- Occupants of the Anti-Virus altitude band (320000-329999) ---"
    $av = $mf | Where-Object { $_.Class -eq 'ANTI-VIRUS' }
    if ($av) { $av | Format-Table -AutoSize Altitude, Service, State, Signer }
    else     { 'None registered.' }
    "`n--- Orphaned registrations (registered but binary absent) ---"
    $orph = $mf | Where-Object Signer -eq 'FILE MISSING'
    if ($orph) { $orph | Format-Table -AutoSize -Wrap Altitude, Class, Service, StartVal, Image }
    else       { 'None.' }
}

Add-Section -Title '33. Storage & Device Class Filter Drivers' -Purpose 'Legacy (non-minifilter) filters that sit in the device stack rather than the file system stack. UpperFilters/LowerFilters on the disk, volume, storage-volume and USB classes are a classic source of I/O latency and boot failures, and are frequently left behind by uninstalled backup, encryption, virtual-drive and overclocking utilities. A filter naming a driver that no longer exists can block a device from starting (Device Manager code 10/39).' -Collector {
    "=== Device class Upper/Lower filters ==="
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p.UpperFilters -or $p.LowerFilters) {
                [PSCustomObject]@{
                    ClassName    = $p.Class
                    ClassGUID    = $_.PSChildName
                    UpperFilters = ($p.UpperFilters -join ', ')
                    LowerFilters = ($p.LowerFilters -join ', ')
                }
            }
        } | Sort-Object ClassName | Format-Table -AutoSize -Wrap

    "`n=== Resolution of each named filter driver ==="
    $names = @()
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $names += @($p.UpperFilters) + @($p.LowerFilters)
        }
    $names | Where-Object { $_ } | Sort-Object -Unique | ForEach-Object {
        $svc = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            FilterDriver = $_
            Registered   = [bool]$svc
            StartVal     = $svc.Start
            Signer       = $(if ($svc) { Get-DriverSigner $svc.ImagePath $_ } else { 'NO SERVICE KEY' })
        }
    } | Format-Table -AutoSize -Wrap

    "`n=== Per-device filter overrides under Enum (non-default only) ==="
    $devFilters = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum' -Recurse -Depth 2 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p.UpperFilters -or $p.LowerFilters) {
                [PSCustomObject]@{
                    Device = ($_.PSPath -replace '.*\\Enum\\', '')
                    Upper  = ($p.UpperFilters -join ', ')
                    Lower  = ($p.LowerFilters -join ', ')
                }
            }
        }
    if ($devFilters) { $devFilters | Select-Object -First $script:TableCap | Format-Table -AutoSize -Wrap }
    else             { 'None found.' }

    "`n=== Non-Microsoft running kernel drivers ==="
    Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' } |
        ForEach-Object {
            $s = Get-DriverSigner $_.PathName $_.Name
            if ($s -notmatch 'Microsoft|^no ImagePath|^signature check failed') {
                [PSCustomObject]@{ Name = $_.Name; DisplayName = $_.DisplayName; StartMode = $_.StartMode; Signer = $s }
            }
        } | Sort-Object Signer, Name | Select-Object -First $script:TableCap | Format-Table -AutoSize -Wrap
}

Add-Section -Title '34. Network Filter Drivers (NDIS / WFP / Winsock)' -Purpose 'Three stacked layers intercept traffic: NDIS lightweight filters bind per-adapter, WFP callouts hook the TCP/IP stack, and Winsock LSPs sit in user mode. Look for: filters bound to adapters they should not touch; VPN or capture filters left bound after uninstall; multiple vendors filtering the same adapter; non-Microsoft Winsock providers (a known malware and adware persistence point); and WFP callouts from products no longer installed. Each layer adds per-packet latency and is a common cause of intermittent connectivity, port exhaustion and DNS failures.' -Collector {
    "=== NDIS bindings (protocols / filters / clients bound to adapters) ==="
    $bind = @(Get-NetAdapterBinding -AllBindings -ErrorAction SilentlyContinue)
    if ($Verbosity -eq 'Full') {
        $bind | Sort-Object Name, ComponentID |
            Format-Table -AutoSize -Wrap Name, DisplayName, ComponentID, Enabled
    }
    else {
        "(grouped by component; run with -Verbosity Full for the per-adapter list)"
        $bind | Group-Object ComponentID | Sort-Object Name |
            Select-Object @{n='ComponentID';e={$_.Name}},
                @{n='DisplayName';e={$_.Group[0].DisplayName}},
                @{n='AdaptersBound';e={$_.Count}},
                @{n='Enabled';e={@($_.Group | Where-Object Enabled).Count}},
                @{n='EnabledOn';e={ (@($_.Group | Where-Object Enabled | ForEach-Object { $_.Name } | Select-Object -Unique -First 6) -join ', ') }} |
            Format-Table -AutoSize -Wrap
    }

    "`n=== Installed network components (distinct filters / protocols / clients) ==="
    # Derived from the bindings: the class-key registry walk returned nothing on Windows 11.
    $bind | Group-Object ComponentID | Sort-Object Name |
        Select-Object @{n='ComponentID';e={$_.Name}}, @{n='Description';e={$_.Group[0].DisplayName}},
            @{n='Kind';e={ if ($_.Name -match '^ms_(tcpip|tcpip6|implat|lltdio|rspndr|server|msclient|pacer|lldp)$') {'in-box'} else {'REVIEW (3rd-party or optional)'} }} |
        Format-Table -AutoSize -Wrap

    "`n=== Windows Filtering Platform: providers, callouts and filter counts ==="
    $wfpFile = Join-Path $env:TEMP "wfpstate_$Stamp.xml"
    try {
        netsh.exe wfp show state file="$wfpFile" | Out-Null
        # Get-Content + [xml] fails on this file's encoding/BOM; XmlDocument.Load detects it from the XML declaration.
        # The file can contain several top-level elements, so wrap the content in a single root before parsing.
        $raw = [System.IO.File]::ReadAllText($wfpFile)
        $raw = $raw -replace '<\?xml[^>]*\?>', ''
        $wfp = New-Object System.Xml.XmlDocument
        $wfp.LoadXml("<wfpRoot>$raw</wfpRoot>")

        "--- Providers ---"
        $wfp.SelectNodes('//providers/item') | ForEach-Object { $_.SelectSingleNode('displayData/name').InnerText } |
            Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
            Select-Object Count, Name | Format-Table -AutoSize

        "`n--- Callout drivers (kernel-mode packet inspection hooks) ---"
        $wfp.SelectNodes('//callouts/item') | ForEach-Object { $_.SelectSingleNode('displayData/name').InnerText } |
            Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
            Select-Object -First $script:TableCap Count, Name | Format-Table -AutoSize -Wrap

        if ($Verbosity -eq 'Full') {
            "`n--- Filters by name (top 40) ---"
            $wfp.SelectNodes('//filters/item') | ForEach-Object { $_.SelectSingleNode('displayData/name').InnerText } |
                Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
                Select-Object -First 40 Count, Name | Format-Table -AutoSize -Wrap
        }
        else { "`n(per-filter list omitted; run with -Verbosity Full to include it)" }

        "`nTotal WFP filters defined: $(@($wfp.SelectNodes('//filters/item')).Count)"
    }
    catch { "WFP state unavailable: $($_.Exception.Message)" }
    finally { Remove-Item $wfpFile -Force -ErrorAction SilentlyContinue }

    "`n=== Winsock catalog (LSP) providers ==="
    $cat = netsh.exe winsock show catalog 2>&1
    $cat | Where-Object { $_ -match '^(Winsock Catalog Provider Entry|Description|Provider Path|Layered Chain Entry)' } |
        ForEach-Object { $_.Trim() } | Select-Object -Unique

    "`n--- Non-Microsoft Winsock provider paths (investigate any result here) ---"
    $lsp = $cat | Where-Object { $_ -match 'Provider Path' } | ForEach-Object { $_.Trim() } | Select-Object -Unique |
        Where-Object { $_ -notmatch 'mswsock|winrnr|napinsp|pnrpnsp|NLAapi|wshbth|nlansp_c|System32\\wshqos' }
    if ($lsp) { $lsp } else { 'None - catalog contains only in-box Microsoft providers.' }
}

Add-Section -Title '35. Network Stack Configuration' -Purpose 'Configuration that governs how the filtered stack behaves. Ephemeral port range and TIME_WAIT behaviour explain Tcpip 4231/4266 exhaustion warnings. Multiple default routes indicate competing VPN adapters. A modified hosts file, an unexpected proxy or a non-standard DNS server are all user-mode traffic redirection - the same effect as a filter, achieved by configuration.' -Collector {
    "=== Ephemeral (dynamic) port ranges ==="
    foreach ($proto in 'tcp', 'udp') {
        foreach ($fam in 'ipv4', 'ipv6') {
            "--- $fam $proto ---"
            netsh.exe int $fam show dynamicport $proto
        }
    }

    "`n=== Current ephemeral port consumption ==="
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    "Total TCP connections: $(@($conns).Count)"
    $conns | Group-Object State | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize
    "`n--- Top 15 processes by TCP connection count ---"
    $conns | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 15 `
        @{n='Conns';e={$_.Count}},
        @{n='PID';e={$_.Name}},
        @{n='Process';e={ try {(Get-Process -Id $_.Name -ErrorAction Stop).ProcessName} catch {'(exited)'} }} |
        Format-Table -AutoSize

    "`n=== TCP global parameters ==="
    netsh.exe int tcp show global
    "`n=== TCP settings profiles ==="
    Get-NetTCPSetting -ErrorAction SilentlyContinue |
        Select-Object SettingName, AutoTuningLevelLocal, CongestionProvider, EcnCapability, Timestamps, MinRto |
        Format-Table -AutoSize
    "`n=== Global offload settings ==="
    Get-NetOffloadGlobalSetting -ErrorAction SilentlyContinue | Format-List

    "`n=== Default routes (more than one indicates competing gateways / VPN) ==="
    Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, NextHop, RouteMetric, InterfaceMetric | Format-Table -AutoSize

    "`n=== DNS servers per interface ==="
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses } |
        Select-Object InterfaceAlias, @{n='Servers';e={$_.ServerAddresses -join ', '}} | Format-Table -AutoSize
    try {
        "`n--- DNS-over-HTTPS configuration ---"
        Get-DnsClientDohServerAddress -ErrorAction Stop | Format-Table -AutoSize ServerAddress, DohTemplate, AutoUpgrade
    } catch { '(DoH cmdlet not available on this build)' }

    "`n=== Proxy configuration ==="
    netsh.exe winhttp show proxy
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue |
        Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | Format-List

    "`n=== Hosts file ==="
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    $entries = Get-Content $hosts -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }
    "Active (non-comment) entries: $(@($entries).Count)"
    if ($entries) { $entries | Select-Object -First $script:TableCap }

    "`n=== Firewall: enabled blocking rules ==="
    $fw = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
    "Enabled rules total: $(@($fw).Count)  |  Blocking: $(@($fw | Where-Object Action -eq 'Block').Count)"
    $fw | Where-Object { $_.Action -eq 'Block' -and $_.Direction -eq 'Outbound' } |
        Select-Object -First $script:TableCap DisplayName, Profile, DisplayGroup | Format-Table -AutoSize -Wrap
}

if ($IncludeIntegrityScan) {
    Add-Section -Title '36. Component Store & System File Integrity' -Purpose 'DISM CheckHealth reports flagged corruption; SFC VerifyOnly detects but does not repair. If either reports corruption, RestoreHealth then a repairing SFC pass is the correct sequence.' -Collector {
        "=== DISM /Online /Cleanup-Image /CheckHealth ==="
        DISM.exe /Online /Cleanup-Image /CheckHealth
        "`n=== DISM /Online /Cleanup-Image /ScanHealth ==="
        DISM.exe /Online /Cleanup-Image /ScanHealth
        "`n=== SFC /VERIFYONLY ==="
        (sfc.exe /VERIFYONLY) -join "`n" -replace "`0", ''
    }
} else {
    Add-Line ''
    Add-Line '## 36. Component Store & System File Integrity'
    Add-Line '```text'
    Add-Line 'SKIPPED - rerun with -IncludeIntegrityScan to include DISM CheckHealth/ScanHealth and SFC /VERIFYONLY.'
    Add-Line '```'
}

if ($IncludeBatteryReport) {
    $BatteryPath = Join-Path $OutputFolder "BatteryReport_$($env:COMPUTERNAME)_$Stamp.html"
    Add-Section -Title '37. Battery' -Purpose 'Compare design capacity to full-charge capacity. Below ~60% indicates a worn battery.' -Collector {
        Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue |
            Select-Object Name, EstimatedChargeRemaining, BatteryStatus, DesignVoltage, Chemistry | Format-List
        powercfg /batteryreport /output "$BatteryPath" 2>&1
        "Full HTML battery report written to: $BatteryPath"
    }
}

# ===========================================================================
# PART 3 - TRIAGE DIGEST
# ===========================================================================
Write-Host "  -> Building triage digest" -ForegroundColor Cyan

$M = @()
$M += New-Metric 'OS build' { $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; "$($cv.DisplayVersion) $($cv.CurrentBuild).$($cv.UBR)" }
$M += New-Metric 'Uptime per WMI tick counter (days)' { [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalDays,1) }
$M += New-Metric 'Fast Startup (Hiberboot) enabled' { try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -EA Stop).HiberbootEnabled -eq 1 } catch { 'unknown' } }
$script:ReconciledUptimeDays = $null
$M += New-Metric 'True days since last power-on (6005, else Diagnostics-Performance 100)' {
    $hiber = try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -EA Stop).HiberbootEnabled } catch { $null }
    $last6005 = Get-EventsSafe -LogName System -Id 6005 -Days 90 -Max 200 | Sort-Object TimeCreated -Descending | Select-Object -First 1
    if (-not $last6005) { $last6005 = Get-EventsSafe -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -Id 100 -Days 90 -Max 200 | Sort-Object TimeCreated -Descending | Select-Object -First 1 }
    if ($last6005) {
        $script:ReconciledUptimeDays = [math]::Round(((Get-Date) - $last6005.TimeCreated).TotalDays, 1)
        $script:ReconciledUptimeDays
    }
    elseif ($hiber -eq 1) { 'unknown - no 6005 or boot-performance event in 90d (log wrapped), Fast Startup enabled: WMI uptime is NOT reliable' }
    else { 'unknown - no 6005 or boot-performance event in 90d' }
} {
    if ($args[0] -match '^unknown') { 'WATCH' }
    elseif ([double]$args[0] -gt ($MaxUptimeDays * 3)) { 'ACTION' }
    elseif ([double]$args[0] -gt $MaxUptimeDays) { 'WATCH' }
    else { 'OK' }
}
$M += New-Metric 'Restart cadence policy' { "every $MaxUptimeDays day(s)" }
$M += New-Metric 'Restart cadence compliance' {
    if ($null -eq $script:ReconciledUptimeDays) { 'cannot verify - see reconciled uptime metric above' }
    elseif ($script:ReconciledUptimeDays -le $MaxUptimeDays) { "within policy ($($script:ReconciledUptimeDays)d of $($MaxUptimeDays)d)" }
    else {
        $mult = [math]::Round($script:ReconciledUptimeDays / $MaxUptimeDays, 1)
        "OVERDUE by $([math]::Round($script:ReconciledUptimeDays - $MaxUptimeDays,1))d - $($mult)x the policy interval"
    }
} {
    if ($args[0] -match '^cannot verify') { 'WATCH' }
    elseif ($args[0] -match '^within policy') { 'OK' }
    elseif ($args[0] -match '(\d+(\.\d+)?)x the policy') { $x=[double]$Matches[1]; if ($x -ge 3) {'ACTION'} else {'WATCH'} }
    else { 'INFO' }
}
$M += New-Metric 'System volume free' { $c = Get-Volume -DriveLetter C; "{0} GB of {1} GB ({2}%)" -f [math]::Round($c.SizeRemaining/1GB,1), [math]::Round($c.Size/1GB,0), [math]::Round(($c.SizeRemaining/$c.Size)*100,1) } { if ($args[0] -match '\(([\d.]+)%\)') { $pct=[double]$Matches[1]; if ($pct -lt 5) {'ACTION - CRITICAL'} elseif ($pct -lt 15) {'ACTION'} else {'OK'} } else {'INFO'} }
$M += New-Metric 'Volumes below 15% free' { @(Get-Volume | Where-Object { $_.DriveLetter -and $_.Size -gt 0 -and ($_.SizeRemaining/$_.Size) -lt 0.15 }).Count } { if ([int]$args[0] -gt 0) {'ACTION'} else {'OK'} }
$M += New-Metric 'Disks not Healthy' { @(Get-PhysicalDisk | Where-Object HealthStatus -ne 'Healthy').Count } { if ([int]$args[0] -gt 0) {'ACTION - CRITICAL'} else {'OK'} }
$M += New-Metric 'SMART uncorrected read/write errors' { $n=0; $who=@(); Get-PhysicalDisk | ForEach-Object { $d=$_; $c = $d | Get-StorageReliabilityCounter -EA SilentlyContinue; if ($c) { $k = [int]$c.ReadErrorsUncorrected + [int]$c.WriteErrorsUncorrected; if ($k -gt 0) { $n += $k; $who += "$($d.FriendlyName) [$($d.BusType)]=$k" } } }; if ($n -eq 0) { '0' } else { "$n  ($($who -join '; '))" } } { if ($args[0] -match '^0$') {'OK'} elseif ($args[0] -match '\[(NVMe|SATA|SAS|RAID|SCSI|ATA)\]') {'ACTION - CRITICAL'} else {'ACTION'} }
$M += New-Metric 'Bugchecks (BSOD) in 90d' { @(Get-EventsSafe -LogName System -Id 1001 -ProviderName 'Microsoft-Windows-WER-SystemErrorReporting' -Days 90 -Max 500).Count } { if ([int]$args[0] -gt 0) {'ACTION'} else {'OK'} }
$M += New-Metric 'Kernel-Power 41 in 90d' { @(Get-EventsSafe -LogName System -Id 41 -ProviderName 'Microsoft-Windows-Kernel-Power' -Days 90 -Max 500).Count } { if ([int]$args[0] -gt 2) {'ACTION'} elseif ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Dirty shutdowns (6008) in 90d' { @(Get-EventsSafe -LogName System -Id 6008 -Days 90 -Max 500).Count } { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric "System log errors in window" { @(Get-EventsSafe -LogName System -Level 1,2).Count } { if ([int]$args[0] -gt 100) {'WATCH'} else {'OK'} }
$M += New-Metric "Application log errors in window" { @(Get-EventsSafe -LogName Application -Level 1,2).Count } { if ([int]$args[0] -gt 100) {'WATCH'} else {'OK'} }
$M += New-Metric 'Crash dump files on disk' { @(@(Get-ChildItem "$env:SystemRoot\Minidump\*.dmp" -EA SilentlyContinue) + @(Get-ChildItem "$env:LOCALAPPDATA\CrashDumps\*.dmp" -EA SilentlyContinue)).Count } { if ([int]$args[0] -gt 5) {'WATCH'} else {'OK'} }
$M += New-Metric 'Pending reboot' { $a = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'); $b = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'); $c2 = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA SilentlyContinue); "CBS=$a WU=$b FileRename=$c2" } { if ($args[0] -match 'CBS=True|WU=True') {'ACTION'} elseif ($args[0] -match 'FileRename=True') {'WATCH'} else {'OK'} }
$M += New-Metric 'Days since last dated hotfix' { $h = Get-HotFix -EA SilentlyContinue | ForEach-Object { try { [datetime]$_.InstalledOn } catch {} } | Sort-Object -Descending | Select-Object -First 1; if ($h) { [math]::Round(((Get-Date)-$h).TotalDays,0) } else { 'none' } } { if ($args[0] -ne 'none' -and [int]$args[0] -gt 45) {'ACTION'} else {'OK'} }
$M += New-Metric 'Problem devices (error code set)' { @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }).Count } { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Auto services not running' { @(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }).Count } { if ([int]$args[0] -gt 15) {'WATCH'} else {'OK'} }
$M += New-Metric 'Defender real-time protection' { (Get-MpComputerStatus).RealTimeProtectionEnabled } { if ($args[0] -eq $true -or $args[0] -eq 'True') {'OK'} else {'ACTION - CRITICAL'} }
$M += New-Metric 'Defender signature age (days)' { $s = Get-MpComputerStatus; [math]::Round(((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays,1) } { if ([double]$args[0] -gt 3) {'ACTION'} else {'OK'} }
$M += New-Metric 'Defender full scan age (days)' { $a = (Get-MpComputerStatus).FullScanAge; if ($a -ge 4294967295) { 'never run' } else { $a } } { if ($args[0] -eq 'never run') {'WATCH'} else {'OK'} }
$M += New-Metric 'Defender exclusions (paths/extensions/processes)' { $p = Get-MpPreference -EA Stop; $a=@($p.ExclusionPath | Where-Object {$_}); $b=@($p.ExclusionExtension | Where-Object {$_}); $c=@($p.ExclusionProcess | Where-Object {$_}); if (($a+$b+$c) -match '^N/A') { 'unknown - needs Administrator' } else { $br = @($a | Where-Object { $_ -match '^[A-Za-z]:\\?\*?$' -or $_ -match '^[A-Za-z]:\\(Users|Windows|Program Files( \(x86\))?)\\?\*?$' }).Count; "$($a.Count)/$($b.Count)/$($c.Count)$(if ($br) { " - $br BROAD" })" } } { if ($args[0] -match 'BROAD') {'ACTION'} elseif ($args[0] -match '^unknown') {'INFO'} else {'INFO'} }
$M += New-Metric 'Secure Boot' { Confirm-SecureBootUEFI } { if ($args[0] -eq $true -or $args[0] -eq 'True') {'OK'} else {'ACTION'} }
$M += New-Metric 'TPM ready' { (Get-Tpm).TpmReady } { if ($args[0] -eq $true -or $args[0] -eq 'True') {'OK'} else {'WATCH'} }
$M += New-Metric 'Unencrypted fixed volumes' { @(Get-BitLockerVolume -EA SilentlyContinue | Where-Object { $_.VolumeType -eq 'OperatingSystem' -or $_.MountPoint -eq 'C:' } | Where-Object ProtectionStatus -eq 'Off').Count } { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Minifilters registered / running' { $t=0;$r=0; Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | ForEach-Object { $i = Join-Path $_.PSPath 'Instances'; if (Test-Path $i) { Get-ChildItem $i -EA SilentlyContinue | ForEach-Object { if ((Get-ItemProperty $_.PSPath -EA SilentlyContinue).Altitude) { $t++ } } } }; $r = @(fltmc.exe filters 2>$null | Where-Object { $_ -match '^\S+\s+\d+\s+' }).Count; "$t registered / $r loaded" } { if ($args[0] -match '/ (\d+) loaded' -and [int]$Matches[1] -gt 20) {'WATCH'} else {'OK'} }
$M += New-Metric 'Orphaned filter registrations (binary missing)' { $n=0; Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | ForEach-Object { $svc = Get-ItemProperty $_.PSPath -EA SilentlyContinue; $i = Join-Path $_.PSPath 'Instances'; if ((Test-Path $i) -and (Get-DriverSigner $svc.ImagePath $_.PSChildName) -eq 'FILE MISSING') { $n++ } }; $n } { if ([int]$args[0] -gt 0) {'ACTION'} else {'OK'} }
$M += New-Metric 'Anti-virus band minifilters (320000-329999)' { $l=@(); Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | ForEach-Object { $n2=$_.PSChildName; $i = Join-Path $_.PSPath 'Instances'; if (Test-Path $i) { Get-ChildItem $i -EA SilentlyContinue | ForEach-Object { $a=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).Altitude; if ($a -and [double]$a -ge 320000 -and [double]$a -lt 330000) { $l += $n2 } } } }; ($l | Sort-Object -Unique) -join ', ' } { if (($args[0] -split ',').Count -gt 2) {'WATCH'} else {'OK'} }
$M += New-Metric 'Non-Microsoft Winsock providers' { @(netsh.exe winsock show catalog 2>$null | Where-Object { $_ -match 'Provider Path' } | Select-Object -Unique | Where-Object { $_ -notmatch 'mswsock|winrnr|napinsp|pnrpnsp|NLAapi|wshbth|nlansp_c|wshqos' }).Count } { if ([int]$args[0] -gt 0) {'ACTION'} else {'OK'} }
$M += New-Metric 'Network adapters present / connected' { $a = Get-NetAdapter -EA SilentlyContinue; "$(@($a).Count) present / $(@($a | Where-Object Status -eq 'Up').Count) up" }
$M += New-Metric 'Default routes' { @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue).Count } { if ([int]$args[0] -gt 1) {'WATCH'} else {'OK'} }
$M += New-Metric 'TCP connections (established)' { @(Get-NetTCPConnection -State Established -EA SilentlyContinue).Count } { if ([int]$args[0] -gt 500) {'WATCH'} else {'OK'} }
$M += New-Metric 'Port exhaustion warnings (Tcpip 4231/4266)' { @(Get-EventsSafe -LogName System -Id 4231,4266 -Days 30 -Max 500).Count } { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Hosts file active entries' { @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -EA SilentlyContinue | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' -and $_ -notmatch '(^|\s)(localhost|host\.docker\.internal|gateway\.docker\.internal|kubernetes\.docker\.internal)\s*$' }).Count } { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Peak process handle count' { $h = (Get-Process | Sort-Object Handles -Descending | Select-Object -First 1); "$($h.Name) = $($h.Handles)" } { if ($args[0] -match '= (\d+)' -and [int]$Matches[1] -gt 50000) {'WATCH'} else {'OK'} }
$M += New-Metric 'System restore points' { @(Get-ComputerRestorePoint -EA SilentlyContinue).Count } { if ([int]$args[0] -eq 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Dominant System-log source (newest 20,000 events)' { $all = @(Get-WinEvent -LogName System -MaxEvents 20000 -EA Stop); $g = $all | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 1; "$($g.Name) = $([math]::Round(100*$g.Count/[math]::Max(1,$all.Count)))%" } { $p = [int]([regex]::Match($args[0],'(\d+)%').Groups[1].Value); if ($p -ge 90) {'ACTION'} elseif ($p -ge 50) {'WATCH'} else {'OK'} }
$M += New-Metric 'System log oldest record' { (Get-WinEvent -LogName System -Oldest -MaxEvents 1 -EA SilentlyContinue).TimeCreated }
$M += New-Metric 'Requested event window (days)' { $DaysBack }

$DigestText = [System.Text.StringBuilder]::new()
[void]$DigestText.AppendLine('## TRIAGE DIGEST (pre-computed - read this first)')
[void]$DigestText.AppendLine('')
[void]$DigestText.AppendLine('These values were computed on the machine at collection time. They are authoritative.')
[void]$DigestText.AppendLine('If the raw evidence sections below are truncated by an upload limit, base your analysis')
[void]$DigestText.AppendLine('on this digest, state which sections were unavailable, and continue.')
[void]$DigestText.AppendLine('')
[void]$DigestText.AppendLine('Flags: ACTION - CRITICAL > ACTION > WATCH > OK > INFO. They are triage hints, not conclusions;')
[void]$DigestText.AppendLine('confirm each against the raw evidence where it is present.')
[void]$DigestText.AppendLine('')
[void]$DigestText.AppendLine('```text')
[void]$DigestText.AppendLine((($M | Format-Table -AutoSize -Wrap Metric, Value, Flag | Out-String -Width 200).TrimEnd()))
[void]$DigestText.AppendLine('```')
[void]$DigestText.AppendLine('')
$counts = $M | Group-Object Flag | Sort-Object Name
[void]$DigestText.AppendLine('Flag totals: ' + (($counts | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  '))

# ===========================================================================
# PART 4 - FINALISE
# ===========================================================================
$Elapsed = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)

Add-Line ''
Add-Line '=== END OF COLLECTED DATA ==='
Add-Line ''
Add-Line '## Collection Metadata'
Add-Line ''
Add-Line "- Sections attempted: 37"
Add-Line "- Verbosity profile: $Verbosity"
Add-Line "- Elapsed seconds: $Elapsed"
Add-Line "- Elevated: $IsAdmin"
Add-Line "- Integrity scan included: $($IncludeIntegrityScan.IsPresent)"
Add-Line "- Battery report included: $($IncludeBatteryReport.IsPresent)"
Add-Line ''
Add-Line '> **AI: begin your analysis now.** Follow the required output structure defined at the'
Add-Line '> top of this file (Executive Summary, Health Scorecard, Findings, Correlation & Timeline,'
Add-Line '> Recommendations with justifications, Quick Wins, Watch List, Data Gaps & Confidence).'
Add-Line '> Cite section numbers and event IDs as evidence for every claim you make.'

$FullText = $Report.ToString().Replace('<<<DIGEST>>>', $DigestText.ToString())

$Limit    = $MaxPartKB * 1024
$FullSize = [System.Text.Encoding]::UTF8.GetByteCount($FullText)
$Written  = @()

if (-not $SplitOutput -and $FullSize -le $Limit) {
    [System.IO.File]::WriteAllText($ReportPath, $FullText, [System.Text.UTF8Encoding]::new($false))
    $Written += $ReportPath
}
else {
    # Split on section boundaries so no section is ever cut in half.
    $chunks = [regex]::Split($FullText, '(?=\r?\n## )') | Where-Object { $_ -ne '' }
    $parts = @()
    do {
        $parts = @()
        $cur = ''
        foreach ($chunk in $chunks) {
            $candidate = $cur + $chunk
            if ($cur -ne '' -and [System.Text.Encoding]::UTF8.GetByteCount($candidate) -gt $Limit) {
                $parts += $cur
                $cur = $chunk
            }
            else { $cur = $candidate }
        }
        if ($cur -ne '') { $parts += $cur }
        $tooMany = ($MaxParts -gt 0 -and $parts.Count -gt $MaxParts)
        if ($tooMany) { $Limit = [int]($Limit * 1.15) }   # grow the per-part size until it fits in MaxParts files
    } while ($tooMany)
    if ($MaxParts -gt 0) {
        $big = @($parts | Where-Object { [System.Text.Encoding]::UTF8.GetByteCount($_) -gt (150KB) }).Count
        if ($big) { Write-Host "NOTE: to fit $MaxParts files, $big part(s) exceed 150 KB; Copilot may truncate them. Re-run with -DaysBack 2 or -Verbosity Compact." -ForegroundColor Yellow }
    }

    $total = $parts.Count
    for ($i = 0; $i -lt $total; $i++) {
        $n = $i + 1
        $titles = ([regex]::Matches($parts[$i], '(?m)^## (.+)$') |
                   ForEach-Object { $_.Groups[1].Value.Trim() }) -join '; '
        if (-not $titles) { $titles = 'analysis instructions and digest' }

        $banner = @"
<!-- MULTI-PART DIAGNOSTIC REPORT -->

# PART $n OF $total - $env:COMPUTERNAME - $Stamp

**Instructions for the AI assistant reading this file:**

- This report was split across $total files because it exceeds a single upload limit.
- The analysis instructions and the TRIAGE DIGEST are in **PART 1**.
- Contents of this part: $titles
- If you have not yet received all $total parts, acknowledge this part briefly, state which
  parts you still need, and wait. Do not begin the full analysis yet.
- **Truncation check.** This part ends with a line reading `=== END OF PART $n OF $total ===`.
  If you cannot see that line, this part was truncated in transit before you received all of
  it. Say so explicitly in your acknowledgement, name the last section heading you actually
  received, and quote its last visible line. Do not describe sections you did not receive as
  "present" - if you only inferred a section exists from its number, you did not receive it.
- Once you have every part you are going to receive, analyse what you have. If some parts
  are missing, produce the report anyway and list the missing parts under Data Gaps.
  **Do not refuse to analyse because the evidence is partial.**

---

"@
        $footer = "`r`n`r`n=== END OF PART $n OF $total ===`r`n"
        if ($n -eq $total) { $footer += "`r`nAll $total parts have now been delivered. Begin the full analysis.`r`n" }
        else { $footer += "`r`nPART $($n + 1) OF $total follows. Acknowledge and wait for it.`r`n" }

        $partPath = Join-Path $OutputFolder ("HealthReport_{0}_{1}_part{2}of{3}.md" -f $env:COMPUTERNAME, $Stamp, $n, $total)
        [System.IO.File]::WriteAllText($partPath, ($banner + $parts[$i] + $footer), [System.Text.UTF8Encoding]::new($false))
        $Written += $partPath
    }
}

$TotalKB = [math]::Round($FullSize / 1KB, 1)

Write-Host ""
Write-Host "Done in $Elapsed seconds." -ForegroundColor Green
Write-Host "Verbosity: $Verbosity   Total content: $TotalKB KB" -ForegroundColor Green
foreach ($f in $Written) {
    Write-Host ("  {0}  ({1} KB)" -f $f, [math]::Round((Get-Item $f).Length / 1KB, 1)) -ForegroundColor Green
}
if ($Written.Count -gt 1) {
    Write-Host ""
    Write-Host "Upload ALL $($Written.Count) parts to the assistant, in order, before asking for analysis." -ForegroundColor Yellow
}
if ($TotalKB -gt 200 -and $Written.Count -eq 1) {
    Write-Host ""
    Write-Host "NOTE: this file may be truncated by chat assistants. Re-run with" -ForegroundColor Yellow
    Write-Host "      -Verbosity Compact -DaysBack 3 -SplitOutput to reduce it." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "PRIVACY: this file contains hostname, usernames, serial numbers, IP addresses and" -ForegroundColor Yellow
Write-Host "         installed software. Review before uploading to any external service." -ForegroundColor Yellow
Write-Host ""

try { Start-Process explorer.exe "/select,`"$($Written[0])`"" } catch { }
