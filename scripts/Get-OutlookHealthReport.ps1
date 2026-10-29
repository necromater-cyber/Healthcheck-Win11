<#
.SYNOPSIS
    Diagnoses likely root causes of Outlook (classic/thick client) slowness on Windows,
    producing a single Markdown report with an embedded AI analysis prompt.

.DESCRIPTION
    Attaches to a RUNNING Outlook process via COM (does not launch Outlook) to inspect
    accounts, connection mode, data files (OST/PST) and their location risk, COM add-ins,
    and folder item counts. Combines this with registry-based cached-mode configuration,
    antivirus real-time-scanning exposure, Windows Search health, network path/latency to
    mail service endpoints, crash/hang history, and live process resource usage.

    Everything is written to ONE Markdown file with a pre-computed triage digest and an
    embedded AI prompt, so a technician (or an AI assistant) can quickly narrow down why a
    specific user's Outlook is slow.

.PARAMETER DaysBack
    Event log lookback window in days. Default 14 (Outlook issues are often intermittent).

.PARAMETER OutputFolder
    Where to write the report. Defaults to the Desktop.

.PARAMETER DeepFolderScan
    Recurse folders beyond the top level, across all stores, up to -MaxFolderDepth and a
    time budget. Off by default (top-level folders in the default store only) to keep the
    scan fast on large mailboxes.

.PARAMETER MaxFolderDepth
    How many levels of subfolders to recurse when scanning. Default 1 (2 with -DeepFolderScan).

.PARAMETER AdditionalEndpoints
    Extra hostnames to test connectivity/latency against - use this for on-premises Exchange
    (CAS array or Autodiscover FQDN). Microsoft 365 endpoints are always tested.

.PARAMETER FolderWarnThreshold / FolderActionThreshold
    Item-count thresholds (per folder) used to flag large folders in the digest.

.EXAMPLE
    .\Get-OutlookHealthReport.ps1

.EXAMPLE
    .\Get-OutlookHealthReport.ps1 -DeepFolderScan -AdditionalEndpoints 'mail.contoso.com'

.NOTES
    Run this UNELEVATED, in the same Windows session as the affected user, with Outlook
    already open. COM automation cannot see across a UAC elevation boundary, so running
    this "as Administrator" will typically fail to attach to the user's Outlook instance.

    PRIVACY: the output includes account display names/SMTP addresses, mailbox file paths,
    and a list of installed add-ins. Review before sharing outside your support workflow.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1, 90)][int]$DaysBack = 14,
    [string]$OutputFolder = [Environment]::GetFolderPath('Desktop'),
    [switch]$DeepFolderScan,
    [ValidateRange(1, 6)][int]$MaxFolderDepth = $(if ($DeepFolderScan) { 2 } else { 1 }),
    [string[]]$AdditionalEndpoints = @(),
    [ValidateRange(1000, 500000)][int]$FolderWarnThreshold = 20000,
    [ValidateRange(1000, 1000000)][int]$FolderActionThreshold = 50000
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# powershell.exe -File passes "a,b" as ONE string, so accept comma-separated endpoints too
# (needed when launched from HealthCheck.exe; harmless when called normally).
$AdditionalEndpoints = @($AdditionalEndpoints | ForEach-Object { $_ -split ',' } |
                         ForEach-Object { $_.Trim() } | Where-Object { $_ })

if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

$Stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportPath = Join-Path $OutputFolder "OutlookHealthReport_$($env:COMPUTERNAME)_$Stamp.md"
$StartTime  = Get-Date
$Report     = [System.Text.StringBuilder]::new()

function Add-Line { param([string]$Text = '') [void]$Report.AppendLine($Text) }

function Get-ShortText {
    param([string]$Text, [int]$Max = 400)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + ' ...[truncated]' }
    return $t
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

function New-Metric {
    param([string]$Name, [scriptblock]$Compute, [scriptblock]$Assess)
    $v = try { & $Compute } catch { 'unavailable' }
    # NB: never compare with -eq '' / -ne 'text' here. PowerShell coerces the right operand to the
    # left operand's type, so 0 -eq '' and $false -eq '' are True and $true -ne 'unavailable' is False.
    $missing = ($null -eq $v) -or (($v -is [string]) -and ([string]::IsNullOrEmpty($v) -or $v -ceq 'unavailable'))
    if ($missing) { $v = 'unavailable' }
    $f = 'INFO'
    if ($Assess -and -not $missing) { $f = try { & $Assess "$v" } catch { 'INFO' } }
    [PSCustomObject]@{ Metric = $Name; Value = "$v"; Flag = $f }
}

# Known third-party add-in vendors frequently implicated in Outlook slowness -
# a name match here is a prompt to investigate, not proof of a problem.
$SuspectAddinPatterns = @(
    'mimecast','proofpoint','symantec','mcafee','trend micro','forcepoint','cisco',
    'imanage','netdocuments','worldox','adobe acrobat','zoom','webex','skype for business',
    'salesforce','smartsheet','dymo','avg','avast','bitdefender','sophos','eset','kaspersky',
    'dlp','encryption','archive','journal','esm','egress','clearswift'
)

Write-Host ""
Write-Host "Outlook Health & Performance Collector" -ForegroundColor Green
Write-Host "Window: last $DaysBack day(s)" -ForegroundColor Green
Write-Host ""

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) {
    Write-Warning "Running elevated. COM attachment to the current user's Outlook session frequently"
    Write-Warning "fails across the UAC boundary. If sections below report 'Outlook not running', close"
    Write-Warning "this window and re-run from a normal (non-elevated) PowerShell prompt."
}

# ---------------------------------------------------------------------------
# Attach to a RUNNING Outlook instance (never launch a new one)
# ---------------------------------------------------------------------------
$OutlookProc    = Get-Process OUTLOOK -ErrorAction SilentlyContinue | Select-Object -First 1
$NewOutlookProc = Get-Process olk -ErrorAction SilentlyContinue | Select-Object -First 1   # 'new Outlook' (WebView-based, no COM)
$OutlookApp     = $null
$OutlookNS      = $null
$OutlookVersion = $null

if ($OutlookProc) {
    try {
        $OutlookApp = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application')
        $OutlookNS  = $OutlookApp.GetNamespace('MAPI')
        $OutlookVersion = $OutlookApp.Version
    }
    catch {
        Write-Warning "Outlook process found but COM attach failed: $($_.Exception.Message)"
        Write-Warning "If this PowerShell window is elevated, re-run it unelevated."
    }
}
$ComOk = [bool]($OutlookApp -and $OutlookNS)

function Get-OutlookFolderCounts {
    param($RootFolder, [int]$MaxDepth = 1, [int]$MaxFolders = 300, [int]$TimeoutSeconds = 25)
    $results = [System.Collections.Generic.List[object]]::new()
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@{Folder = $RootFolder; Depth = 0})
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt $MaxFolders -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $node = $queue.Dequeue()
        $f = $node.Folder
        $visited++
        $count  = try { $f.Items.Count } catch { -1 }
        $unread = try { $f.UnReadItemCount } catch { -1 }
        $path   = try { $f.FolderPath } catch { $f.Name }
        $results.Add([PSCustomObject]@{ Folder = $path; Items = $count; Unread = $unread })
        if ($node.Depth -lt $MaxDepth) {
            try { foreach ($sub in $f.Folders) { $queue.Enqueue(@{Folder = $sub; Depth = $node.Depth + 1}) } }
            catch { }
        }
    }
    [PSCustomObject]@{
        Results   = $results
        TimedOut  = ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds)
        Truncated = ($visited -ge $MaxFolders)
    }
}

function Get-PathLocationRisk {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'unknown' }
    if ($Path -match '^\\\\') { return 'NETWORK (UNC path)' }
    try {
        $drive = (Get-Item $Path -ErrorAction Stop).PSDrive.Name + ':'
        $vol = Get-Volume -DriveLetter $drive.TrimEnd(':') -ErrorAction SilentlyContinue
        if ($vol -and $vol.DriveType -eq 'Network') { return 'NETWORK (mapped drive)' }
        if ($vol -and $vol.DriveType -eq 'Removable') { return 'REMOVABLE media' }
    } catch { }
    if ($Path -match '\\OneDrive|\\SharePoint') { return 'ONEDRIVE/SHAREPOINT SYNCED FOLDER' }
    return 'Local fixed disk'
}

# ===========================================================================
# PART 1 - THE AI ANALYSIS PROMPT
# ===========================================================================
$AiPrompt = @'
<!-- ======================================================================
     AI ANALYSIS PROMPT - READ THIS FIRST, THEN ANALYSE THE DATA BELOW
     ====================================================================== -->

# INSTRUCTIONS FOR THE AI ASSISTANT

## 1. Your role
You are a Microsoft 365 / Exchange messaging support engineer performing root-cause
triage on a single user's slow Outlook (classic thick client). Everything after
`=== BEGIN COLLECTED DATA ===` is raw evidence collected from that user's machine, plus a
pre-computed TRIAGE DIGEST. Treat it as the sole source of truth - do not invent add-ins,
account names, file sizes or event details that are not present in the data.

## 1a. Handling incomplete data - do not refuse
Outlook may not have been running when this was collected, in which case every COM-based
section (accounts, data files, add-ins, folder counts) is marked "Outlook not running -
skipped." This is expected, not a fault in the tool. Always produce the full report using
whatever evidence is present - the TRIAGE DIGEST and the registry/network/event-log sections
do not depend on Outlook being open. List anything unavailable under Data Gaps with reduced
confidence. Never end your response asking for a re-run instead of analysing what you have.

## 2. How to reason
- Work from evidence to conclusion. Cite the section, metric name, or event detail behind
  every claim.
- Outlook slowness is very often **compounding**, not singular: a large OST on a network
  path, with no antivirus exclusion, plus three heavyweight add-ins, is one story that adds
  up - not four unrelated findings. Look for these combinations explicitly.
- Distinguish a genuine root cause from a contributing factor. A 60 GB local OST is a
  contributing factor; that same OST on a mapped network drive is very likely the root cause.
- Weight the "known suspect" add-in list as a prompt to investigate, not a verdict - some
  security/DLP add-ins are mandatory and cannot simply be removed. Frame those recommendations
  around updating, reconfiguring, or scheduling around the add-in, not just disabling it.
- A single-instance snapshot cannot prove intermittent problems. Say so where relevant and
  suggest what to capture next time the slowness is actively occurring (e.g. a Process Monitor
  trace, or "does this correlate with Outlook's search box, sending mail, or opening the app").

## 3. Severity model
- **CRITICAL** - Outlook is effectively unusable, data integrity is at risk (e.g. corrupt
  data file, disk almost full), or the mailbox cannot sync at all.
- **HIGH** - A specific, well-evidenced factor very likely explains the reported slowness.
- **MEDIUM** - A configuration or environmental factor that measurably degrades performance
  but is not the primary suspect.
- **LOW** - Hygiene or best-practice gaps unlikely to explain the reported symptom on their own.
- **INFORMATIONAL / NOISE** - Present but not actionable; explain why.

## 4. Required output structure

### A. Executive Summary
Under 150 words. Plain language. State your leading hypothesis for the slowness, your
confidence in it, and the single next action.

### B. Health Scorecard
| Domain | Score /10 | Verdict | Key Evidence |
|---|---|---|---|
| Data File Health (OST/PST) | | | |
| Cached Mode & Sync Configuration | | | |
| Add-ins | | | |
| Folder / Mailbox Size | | | |
| Antivirus Exposure | | | |
| Search & Indexing | | | |
| Network Path to Mail Service | | | |
| System Resource Contention | | | |
| Crash/Hang Stability | | | |
| **Overall** | | | |

### C. Findings
One per issue, ordered by severity:
**F-01 | [SEVERITY] | Title**
- Observation / Evidence (cite section + specific value) / Interpretation / Likely root
  cause (confidence High/Medium/Low) / Impact on the user's experience.

### D. Compounding Factors
Explicitly call out any combination of findings that multiply each other's impact (see
"How to reason" above). This section is often more useful than any single finding.

### E. Recommendations
Ordered by priority, each with: Justification (tied to a specific finding) / Why this over
alternatives you considered and rejected / Exact steps (menu paths and/or PowerShell/registry
commands) / Verification (what should measurably improve, and how to check) / Rollback.

Before recommending anything destructive (recreating the OST, deleting a PST, resetting the
profile, repairing/reinstalling Office), require confirmation that the mailbox is server-held
(Exchange/M365, so an OST rebuild is safe) or that a PST has been backed up. Never suggest a
registry edit to disable Outlook's own crash-protection or add-in resiliency features.

### F. Quick Wins
Up to 5 actions completable in the same support session.

### G. Watch List
Items not yet a problem but worth monitoring, with the signal that would escalate them.

### H. Data Gaps & Confidence Statement
What could not be assessed (especially "Outlook not running" if applicable) and your overall
confidence (High/Medium/Low).

## 5. Constraints
- Prefer built-in tooling and documented UI paths (File > Options > Add-ins; File > Account
  Settings; Outlook's own Search Tools > Indexing Status) over third-party utilities.
- Do not recommend "PST/OST repair tools" other than Microsoft's own SCANPST.EXE.
- If the evidence shows no meaningful problem, say the configuration looks healthy and ask
  what the user was doing when it felt slow - don't manufacture findings.

=== BEGIN COLLECTED DATA ===
'@
Add-Line $AiPrompt
Add-Line ''
Add-Line '# Outlook Health & Performance Collection'
Add-Line ''
Add-Line "- **Collector version:** 1.3"
if ($env:HEALTHCHECK_LAUNCHER) { Add-Line "- **Launcher:** $env:HEALTHCHECK_LAUNCHER" }
Add-Line "- **Computer:** $env:COMPUTERNAME"
Add-Line "- **User:** $env:USERDOMAIN\$env:USERNAME"
Add-Line "- **Collected at:** $($StartTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
Add-Line "- **Event window:** last $DaysBack day(s)"
Add-Line "- **Outlook running / COM attached:** $ComOk"
Add-Line "- **Ran elevated:** $IsAdmin  (should normally be False - see script notes if COM attach failed)"
Add-Line ''

# ===========================================================================
# PART 2 - COLLECTION
# ===========================================================================
Write-Host "Collecting..." -ForegroundColor Yellow

Add-Section -Title '01. Outlook Process & Version' -Purpose '32-bit Outlook with a large mailbox is a well-known perf ceiling. An outdated Click-to-Run build can also carry known perf regressions since fixed in later builds.' -Collector {
    if (-not $OutlookProc) {
        if ($NewOutlookProc) {
            'The NEW Outlook for Windows (olk.exe) is running, not classic Outlook (OUTLOOK.EXE).'
            'This collector inspects classic Outlook through COM; the new Outlook has no COM interface and its data lives in the cloud,'
            'so the account, add-in, data-file and folder sections cannot be collected. The network, antivirus and search sections below'
            'still apply. To test classic Outlook: close the new Outlook, open classic Outlook, then re-run as the normal user.'
        }
        else {
            'Outlook (classic, OUTLOOK.EXE) is not currently running. Ask the user to open it and re-run for full diagnostics.'
            if ($IsAdmin) { 'NOTE: this run was elevated. Even with Outlook open, COM automation cannot cross the elevation boundary - run again as the normal user.' }
        }
        return
    }
    $bitness = if ($OutlookProc.Path -match '\(x86\)') { '32-bit' } else { '64-bit' }
    $ver = try { (Get-Item $OutlookProc.Path).VersionInfo } catch { $null }
    [PSCustomObject]@{
        Path              = $OutlookProc.Path
        Bitness_Heuristic = $bitness
        FileVersion       = $ver.FileVersion
        ProductVersion    = $ver.ProductVersion
        COMVersion        = $OutlookVersion
        COMAttached       = $ComOk
        StartTime         = $OutlookProc.StartTime
        RunningHours      = [math]::Round(((Get-Date) - $OutlookProc.StartTime).TotalHours, 1)
    } | Format-List

    "=== Click-to-Run configuration ==="
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue |
        Select-Object VersionToReport, UpdateChannel, Platform, ClientCulture |
        Format-List
    "(For full update history, check File > Office Account > About Outlook, and Update Options > View Updates.)"
}

Add-Section -Title '02. Live Process Resource Usage' -Purpose 'High CPU sustained (not a brief spike), or Outlook reported Not Responding, points to a hang - often add-in or network related rather than a generic slow feel.' -Collector {
    if (-not $OutlookProc) { 'Outlook is not running.'; return }
    $procs = Get-Process OUTLOOK -ErrorAction SilentlyContinue
    "OUTLOOK.EXE process count: $(@($procs).Count) $(if (@($procs).Count -gt 1) {'- multiple instances is unusual and often indicates a hung prior session.'})"
    $procs | Select-Object Id, @{n='CPU_s';e={[math]::Round($_.CPU,1)}},
        @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}}, Handles,
        @{n='Threads';e={$_.Threads.Count}}, Responding, StartTime | Format-Table -AutoSize

    "=== Overall system resource context ==="
    $os = Get-CimInstance Win32_OperatingSystem
    [PSCustomObject]@{
        TotalRAM_GB   = [math]::Round($os.TotalVisibleMemorySize/1MB, 2)
        FreeRAM_GB    = [math]::Round($os.FreePhysicalMemory/1MB, 2)
        PctRAMUsed    = [math]::Round((1 - ($os.FreePhysicalMemory/$os.TotalVisibleMemorySize))*100, 1)
    } | Format-List
    "=== Top 5 processes by CPU (excluding Outlook) - checking for resource contention ==="
    Get-Process | Where-Object { $_.ProcessName -ne 'OUTLOOK' -and $_.CPU } | Sort-Object CPU -Descending |
        Select-Object -First 5 ProcessName, Id, @{n='CPU_s';e={[math]::Round($_.CPU,1)}},
        @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}} | Format-Table -AutoSize
}

Add-Section -Title '03. Accounts & Connection Status' -Purpose 'ExchangeConnectionMode reveals whether cached mode is actually connected/syncing vs stuck disconnected. Multiple Exchange accounts, or a mix of account types, changes where to look next.' -Collector {
    if (-not $ComOk) { 'Outlook not running - skipped.'; return }
    "Profile name: $($OutlookNS.CurrentProfileName)"
    "Namespace ExchangeConnectionMode: $($OutlookNS.ExchangeConnectionMode)"
    "  (olOnline/olCachedConnectedFull are healthy; olCachedDisconnected or olDisconnected explain most 'stuck' symptoms)"
    "`n=== Accounts ==="
    $OutlookNS.Accounts | ForEach-Object {
        $mode = try { $_.ExchangeConnectionMode } catch { 'n/a' }
        [PSCustomObject]@{
            DisplayName = $_.DisplayName
            AccountType = $_.AccountType
            SmtpAddress = $(try { $_.SmtpAddress } catch { 'n/a' })
            ExchangeConnectionMode = $mode
        }
    } | Format-Table -AutoSize -Wrap
}

Add-Section -Title '04. Data Files (OST/PST) & Location Risk' -Purpose 'A data file on a network share, mapped drive, or inside a OneDrive-synced folder is one of the single most common root causes of severe, sustained Outlook slowness - every MAPI operation pays network/sync latency. Also check free space on the hosting volume.' -Collector {
    if (-not $ComOk) { 'Outlook not running - skipped.'; return }
    $OutlookNS.Stores | ForEach-Object {
        $store = $_
        $path = try { $store.FilePath } catch { $null }
        $risk = if ($path) { Get-PathLocationRisk -Path $path } else { 'N/A (no local file - online-only store)' }
        $sizeGB = $null; $freeGB = $null
        if ($path -and (Test-Path $path)) {
            $sizeGB = [math]::Round((Get-Item $path).Length/1GB, 2)
            try {
                $vol = Get-Volume -DriveLetter ((Get-Item $path).PSDrive.Name) -ErrorAction Stop
                $freeGB = [math]::Round($vol.SizeRemaining/1GB, 2)
            } catch { }
        }
        [PSCustomObject]@{
            Store       = $store.DisplayName
            ExchangeStoreType = $(try { $store.ExchangeStoreType } catch { 'n/a' })
            FilePath    = $path
            LocationRisk = $risk
            Size_GB     = $sizeGB
            HostVolumeFree_GB = $freeGB
        }
    } | Format-List
}

Add-Section -Title '05. Cached Exchange Mode & Sync Window' -Purpose 'A short sync window (fewer months) reduces OST size and improves perf; "All" with many years of mail on a slow disk is a common contributor. Download Shared Folders adds every additional mailbox to the local OST.' -Collector {
    $ver = if ($OutlookVersion) { $OutlookVersion } else {
        (Get-ChildItem 'HKCU:\Software\Microsoft\Office' -ErrorAction SilentlyContinue |
         Where-Object { $_.PSChildName -match '^\d+\.\d+$' -and (Test-Path (Join-Path $_.PSPath 'Outlook')) } |
         Sort-Object { [double]$_.PSChildName } -Descending | Select-Object -First 1).PSChildName
    }
    if (-not $ver) { 'Could not determine Outlook registry version (Outlook not running and no profile found).'; return }
    "Outlook registry version in use: $ver"
    $cmKey = "HKCU:\Software\Microsoft\Office\$ver\Outlook\Cached Mode"
    $cm = Get-ItemProperty $cmKey -ErrorAction SilentlyContinue
    if ($cm) {
        $syncMap = @{0='All';1='3 months';3='6 months';6='12 months';12='24 months';24='36 months';36='All'}
        [PSCustomObject]@{
            CachedModeEnabled = $(if ($null -ne $cm.Enable) { [bool]$cm.Enable } else { 'not set (default on for new profiles)' })
            SyncWindowMonths  = $(if ($null -ne $cm.SyncWindowSetting) { $syncMap[[int]$cm.SyncWindowSetting] } else { 'not set' })
        } | Format-List
    } else { 'Cached Mode registry key not present (default settings in effect, or Outlook has never been configured on this profile).' }
    "(Verify Download Shared Folders / Download Public Folder Favorites via File > Account Settings > double-click account > slider dialog - not reliably readable from the registry across builds.)"
}

Add-Section -Title '06. COM Add-ins' -Purpose 'Add-ins are the single most common cause of Outlook slowness at startup and during send/receive. Outlook itself shows exact load time and a "Slow" designation under File > Options > Add-ins > COM Add-ins > Manage - check there for precise numbers this script cannot extract.' -Collector {
    if (-not $ComOk) { 'Outlook not running - skipped.'; return }
    $addins = $OutlookApp.COMAddIns | ForEach-Object {
        $suspect = $false
        foreach ($p in $SuspectAddinPatterns) { if ($_.Description -match $p -or $_.ProgId -match $p) { $suspect = $true; break } }
        [PSCustomObject]@{
            Description = $_.Description
            ProgId      = $_.ProgId
            Connected   = $_.Connect
            KnownSuspectVendor = $suspect
        }
    }
    "Total registered COM add-ins: $(@($addins).Count)   |   Currently connected: $(@($addins | Where-Object Connected).Count)"
    $addins | Sort-Object Connected -Descending | Format-Table -AutoSize -Wrap
    "`n--- Connected add-ins matching known-suspect vendor patterns (investigate, do not assume guilty) ---"
    $s = $addins | Where-Object { $_.Connected -and $_.KnownSuspectVendor }
    if ($s) { $s | Format-Table -AutoSize -Wrap Description, ProgId }
    else { 'None matched.' }

    "`n=== Outlook-disabled items (crashed or flagged too slow at startup) ==="
    $verKey = if ($OutlookVersion) { $OutlookVersion } else { '16.0' }
    $resKey = "HKCU:\Software\Microsoft\Office\$verKey\Outlook\Resiliency\DisabledItems"
    if (Test-Path $resKey) {
        $n = (Get-Item $resKey).ValueCount
        "Outlook has auto-disabled $n item(s) due to a prior crash or startup failure."
        "Entry names are opaque hashes; check File > Options > Add-ins > Disabled Items in Outlook's UI to identify them."
    } else { 'No auto-disabled items recorded.' }
}

Add-Section -Title '07. Folder Item Counts' -Purpose "Very large folders (tens of thousands of items) slow rendering, sorting and search regardless of hardware - this is a well-documented Outlook/MAPI scaling limit, not a bug. Default scan covers the primary store's top level only; use -DeepFolderScan for full coverage." -Collector {
    if (-not $ComOk) { 'Outlook not running - skipped.'; return }
    $stores = if ($DeepFolderScan) { $OutlookNS.Stores } else { @($OutlookNS.DefaultStore) }
    $allResults = [System.Collections.Generic.List[object]]::new()
    $anyTimeout = $false; $anyTruncated = $false
    foreach ($store in $stores) {
        $root = try { $store.GetRootFolder() } catch { $null }
        if (-not $root) { continue }
        $r = Get-OutlookFolderCounts -RootFolder $root -MaxDepth $MaxFolderDepth
        $anyTimeout = $anyTimeout -or $r.TimedOut
        $anyTruncated = $anyTruncated -or $r.Truncated
        foreach ($item in $r.Results) { $allResults.Add($item) }
    }
    "Scope: $(if ($DeepFolderScan) {'all stores'} else {'default store only'}), max depth $MaxFolderDepth"
    if ($anyTimeout)   { "NOTE: scan hit its time budget before completing - results are partial." }
    if ($anyTruncated) { "NOTE: scan hit its folder-count cap before completing - results are partial." }
    "`n--- All folders scanned, sorted by item count ---"
    $allResults | Sort-Object Items -Descending | Format-Table -AutoSize -Wrap
    "`n--- Folders over the warn threshold ($FolderWarnThreshold items) ---"
    $big = $allResults | Where-Object { $_.Items -ge $FolderWarnThreshold }
    if ($big) { $big | Sort-Object Items -Descending | Format-Table -AutoSize -Wrap }
    else { 'None.' }
}

Add-Section -Title '08. Antivirus Real-Time Scanning Exposure' -Purpose 'If the OST/PST path and OUTLOOK.EXE are not excluded from real-time AV scanning, every MAPI write can be intercepted and scanned, adding latency to nearly every action in Outlook. If a third-party AV is the active engine, verify exclusions there instead - Defender exclusions are irrelevant if Defender is not the active real-time scanner.' -Collector {
    "=== Registered security products ==="
    try {
        Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            Select-Object displayName, productState | Format-Table -AutoSize
    } catch { "SecurityCenter2 unavailable: $($_.Exception.Message)" }

    "`n=== Microsoft Defender exclusions ==="
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        "Excluded paths:`n$(($pref.ExclusionPath | Out-String).Trim())"
        "Excluded processes:`n$(($pref.ExclusionProcess | Out-String).Trim())"
        if (@($pref.ExclusionProcess) -match '^N/A') {
            # Without Administrator, Defender returns the text "N/A: Must be an administrator to view exclusions".
            "OUTLOOK.EXE process exclusion present: UNKNOWN (Defender hides exclusions from a non-elevated session)."
            "To check by hand: Windows Security > Virus & threat protection > Manage settings > Exclusions."
            $outlookExcluded = $null
        }
        else {
        $outlookExcluded = $pref.ExclusionProcess -contains 'OUTLOOK.EXE' -or $pref.ExclusionProcess -contains 'outlook.exe'
        "OUTLOOK.EXE process exclusion present: $outlookExcluded"
        if ($ComOk) {
            $paths = $OutlookNS.Stores | ForEach-Object { try { $_.FilePath } catch { $null } } | Where-Object { $_ }
            foreach ($p in $paths) {
                $dir = Split-Path $p -Parent
                $covered = $pref.ExclusionPath | Where-Object { $dir -like "$_*" -or $p -like "$_*" }
                "Data file '$p' covered by an exclusion: $([bool]$covered)"
            }
        }
        }
    } catch { "Get-MpPreference unavailable (third-party AV may be the active engine - check its console directly): $($_.Exception.Message)" }
}

Add-Section -Title '09. Search & Indexing Health' -Purpose 'Outlook Instant Search depends entirely on the Windows Search service. If the service is stopped/disabled, or the indexer is still catching up, search feels instant-slow and can make the whole app feel sluggish while it churns. Verify true index completion via Outlook''s own search box > Search Tools > Indexing Status.' -Collector {
    "=== Windows Search service ==="
    Get-Service WSearch -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-List
    "=== Indexer process (if actively catching up, expect visible CPU/disk use) ==="
    Get-Process SearchIndexer -ErrorAction SilentlyContinue | Select-Object Id,
        @{n='CPU_s';e={[math]::Round($_.CPU,1)}}, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}} |
        Format-Table -AutoSize
    "(Authoritative check: in Outlook, click the search box, then Search Tools (ribbon) > Indexing Status.)"
}

Add-Section -Title '10. Network Path to Mail Service' -Purpose 'High latency or failed connectivity to the mail service explains slow send/receive and folder switching even when the local machine is otherwise healthy. VPNs without split tunnelling commonly add 100+ ms of unnecessary round-trip to every request.' -Collector {
    $targets = @('outlook.office365.com', 'outlook.office.com', 'outlook.live.com') + $AdditionalEndpoints   # outlook.live.com = personal Outlook.com / Microsoft account mail
    foreach ($t in ($targets | Select-Object -Unique)) {
        try {
            $r = Test-NetConnection -ComputerName $t -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction Stop
            # ICMP is blocked by Microsoft 365, so time three real TCP connects instead (includes DNS lookup).
            $ms = @(1..3 | ForEach-Object {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $c = New-Object System.Net.Sockets.TcpClient
                try { if ($c.ConnectAsync($t, 443).Wait(4000)) { $sw.ElapsedMilliseconds } } catch { } finally { $c.Close() }
            })
            $rtt = if ($ms.Count) { "min $(($ms | Measure-Object -Minimum).Minimum) / max $(($ms | Measure-Object -Maximum).Maximum) ms" } else { 'timeout' }
            "{0,-30} TCP443={1,-6} ResolvedIP={2,-16} TcpConnect={3}" -f $t, $r.TcpTestSucceeded, $r.RemoteAddress, $rtt
        } catch { "{0,-30} test failed: {1}" -f $t, $_.Exception.Message }
    }
    "`n=== Proxy configuration ==="
    netsh.exe winhttp show proxy
    "`n=== VPN / virtual adapters present ==="
    Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'VPN|TAP|Wintun|PPP|Virtual' } |
        Select-Object Name, InterfaceDescription, Status | Format-Table -AutoSize -Wrap
    "`n=== Default routes (more than one indicates a competing gateway, e.g. split-tunnel misconfiguration) ==="
    Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, NextHop, RouteMetric | Format-Table -AutoSize
}

Add-Section -Title '11. Outlook Crash & Hang History' -Purpose 'A recent crash or hang pattern (especially clustering around a specific time of day, e.g. every morning at first send/receive) often points at a specific add-in or a corrupt data file rather than general slowness.' -Collector {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000,1002; StartTime = (Get-Date).AddDays(-$DaysBack) } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'OUTLOOK\.EXE' }
    if (-not $ev -or $ev.Count -eq 0) { "No OUTLOOK.EXE crash or hang events in the last $DaysBack day(s)."; return }
    "Total OUTLOOK.EXE crash/hang events: $($ev.Count)"
    $ev | Sort-Object TimeCreated -Descending | Select-Object -First 15 TimeCreated, Id,
        @{n='Detail';e={ Get-ShortText $_.Message 350 }} | Format-List
}

Add-Section -Title '12. Outlook Performance-Relevant Settings' -Purpose 'Hardware graphics acceleration interacts with GPU driver quality in both directions - report the state as context, not a verdict, unless paired with a known-bad GPU driver.' -Collector {
    $ver = if ($OutlookVersion) { $OutlookVersion } else { '16.0' }
    $genKey = "HKCU:\Software\Microsoft\Office\$ver\Outlook\Options\General"
    $g = Get-ItemProperty $genKey -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        DisableHardwareAcceleration = $(if ($null -ne $g.DisableHardwareAcceleration) { [bool]$g.DisableHardwareAcceleration } else { 'not set (default: enabled)' })
    } | Format-List
    "(Send/Receive interval and Download Shared Folders are best verified in Outlook's UI - registry"
    "locations for these vary across builds and are not reliably read here.)"
}

# ===========================================================================
# PART 3 - TRIAGE DIGEST
# ===========================================================================
Write-Host "  -> Building triage digest" -ForegroundColor Cyan

$M = @()
$M += New-Metric 'Outlook running / COM attached' { $ComOk }
$M += New-Metric 'OUTLOOK.EXE process count' { @(Get-Process OUTLOOK -ErrorAction SilentlyContinue).Count } { if ([int]$args[0] -gt 1) {'WATCH'} else {'OK'} }
$M += New-Metric 'Outlook responding' { $p = Get-Process OUTLOOK -EA SilentlyContinue | Select-Object -First 1; if ($p) { $p.Responding } else { 'n/a - not running' } } { if ($args[0] -eq 'False') {'ACTION - CRITICAL'} else {'OK'} }
$M += New-Metric 'Largest data file location risk' {
    if (-not $ComOk) { 'unknown - Outlook not running' }
    else {
        $risks = $OutlookNS.Stores | ForEach-Object { try { Get-PathLocationRisk -Path $_.FilePath } catch { $null } } | Where-Object { $_ }
        if ($risks -match 'NETWORK' -or $risks -match 'ONEDRIVE') { ($risks | Where-Object { $_ -match 'NETWORK|ONEDRIVE' } | Select-Object -First 1) }
        elseif ($risks) { 'Local fixed disk (all stores)' }
        else { 'unknown' }
    }
} { if ($args[0] -match 'NETWORK|ONEDRIVE') {'ACTION - CRITICAL'} elseif ($args[0] -match 'unknown') {'WATCH'} else {'OK'} }
$M += New-Metric 'Largest OST/PST size (GB)' {
    if (-not $ComOk) { 'unknown - Outlook not running' }
    else {
        $sizes = $OutlookNS.Stores | ForEach-Object { $p = try { $_.FilePath } catch { $null }; if ($p -and (Test-Path $p)) { [math]::Round((Get-Item $p).Length/1GB,2) } }
        if ($sizes) { ($sizes | Measure-Object -Maximum).Maximum } else { 'unknown' }
    }
} { if ($args[0] -match '^unknown') {'WATCH'} elseif ([double]$args[0] -gt 50) {'WATCH'} else {'OK'} }
$M += New-Metric 'Connected COM add-in count' { if ($ComOk) { @($OutlookApp.COMAddIns | Where-Object Connect).Count } else { 'unknown - Outlook not running' } } { if ($args[0] -match '^unknown') {'WATCH'} elseif ([int]$args[0] -gt 8) {'WATCH'} else {'OK'} }
$M += New-Metric 'Connected add-ins matching known-suspect vendors' {
    if (-not $ComOk) { 'unknown - Outlook not running' }
    else {
        $n = 0
        $OutlookApp.COMAddIns | Where-Object Connect | ForEach-Object { $ai=$_; foreach ($p in $SuspectAddinPatterns) { if ($ai.Description -match $p) { $n++; break } } }
        $n
    }
} { if ($args[0] -match '^unknown') {'WATCH'} elseif ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Outlook auto-disabled items (crash/slow history)' {
    $verKey = if ($OutlookVersion) { $OutlookVersion } else { '16.0' }
    $k = "HKCU:\Software\Microsoft\Office\$verKey\Outlook\Resiliency\DisabledItems"
    if (Test-Path $k) { (Get-Item $k).ValueCount } else { 0 }
} { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Largest folder item count' {
    if (-not $ComOk) { 'unknown - Outlook not running' }
    else {
        $root = try { $OutlookNS.DefaultStore.GetRootFolder() } catch { $null }
        if ($root) { $r = Get-OutlookFolderCounts -RootFolder $root -MaxDepth 1 -TimeoutSeconds 15; if ($r.Results.Count) { ($r.Results | Measure-Object Items -Maximum).Maximum } else { 'unknown' } }
        else { 'unknown' }
    }
} { if ($args[0] -match '^unknown') {'WATCH'} elseif ([double]$args[0] -gt $FolderActionThreshold) {'ACTION'} elseif ([double]$args[0] -gt $FolderWarnThreshold) {'WATCH'} else {'OK'} }
$M += New-Metric 'Windows Search service state' { (Get-Service WSearch -EA SilentlyContinue).Status } { if ($args[0] -ne 'Running') {'ACTION'} else {'OK'} }
$M += New-Metric 'Active AV product count' { @(try { Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -EA Stop } catch { @() }).Count }
$M += New-Metric 'Defender OUTLOOK.EXE process exclusion' { try { $ep = @((Get-MpPreference -EA Stop).ExclusionProcess); if ($ep -match '^N/A') { 'unknown - exclusions need Administrator' } else { $ep -contains 'OUTLOOK.EXE' } } catch { 'unknown - Get-MpPreference unavailable' } } { if ($args[0] -eq 'False') {'WATCH'} elseif ($args[0] -match '^unknown') {'INFO'} else {'OK'} }
$M += New-Metric 'Mail endpoints reachable on TCP 443' {
    $eps = 'outlook.office365.com', 'outlook.office.com', 'outlook.live.com'
    $ok = 0
    foreach ($e in $eps) { try { if ((Test-NetConnection -ComputerName $e -Port 443 -WarningAction SilentlyContinue -EA Stop).TcpTestSucceeded) { $ok++ } } catch { } }
    "$ok of $($eps.Count)"
} { if ($args[0] -match '^0 of') {'ACTION - CRITICAL'} elseif ($args[0] -match '^(\d+) of \1$') {'OK'} else {'ACTION'} }
$M += New-Metric 'Outlook flavour' { if ($OutlookProc) { 'classic (OUTLOOK.EXE)' } elseif ($NewOutlookProc) { 'NEW Outlook (olk.exe) - COM sections cannot be collected' } else { 'not running' } } { if ($args[0] -match '^NEW|^not running') {'WATCH'} else {'OK'} }
$M += New-Metric 'VPN/virtual network adapters present' { @(Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'VPN|TAP|Wintun|PPP|Virtual' }).Count } { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'OUTLOOK.EXE crash/hang events in window' { @(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000,1002;StartTime=(Get-Date).AddDays(-$DaysBack)} -MaxEvents 500 -EA SilentlyContinue | Where-Object { $_.Message -match 'OUTLOOK\.EXE' }).Count } { if ([int]$args[0] -gt 0) {'WATCH'} else {'OK'} }
$M += New-Metric 'Exchange connection mode' { if ($ComOk) { $OutlookNS.ExchangeConnectionMode } else { 'unknown - Outlook not running' } } { if ($args[0] -match 'Disconnected') {'ACTION'} elseif ($args[0] -match '^unknown') {'WATCH'} else {'OK'} }

$DigestText = [System.Text.StringBuilder]::new()
[void]$DigestText.AppendLine('## TRIAGE DIGEST (pre-computed - read this first)')
[void]$DigestText.AppendLine('')
[void]$DigestText.AppendLine('Flags: ACTION - CRITICAL > ACTION > WATCH > OK > INFO. Triage hints, not conclusions -')
[void]$DigestText.AppendLine('confirm each against the raw evidence sections where present.')
[void]$DigestText.AppendLine('')
[void]$DigestText.AppendLine('```text')
[void]$DigestText.AppendLine((($M | Format-Table -AutoSize -Wrap Metric, Value, Flag | Out-String -Width 200).TrimEnd()))
[void]$DigestText.AppendLine('```')
$counts = $M | Group-Object Flag | Sort-Object Name
[void]$DigestText.AppendLine('')
[void]$DigestText.AppendLine('Flag totals: ' + (($counts | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  '))

# Splice digest in right after the header block
$FullText = $Report.ToString()
$marker = "- **Ran elevated:** $IsAdmin  (should normally be False - see script notes if COM attach failed)"
$FullText = $FullText.Replace($marker, $marker + "`r`n`r`n" + $DigestText.ToString())

# ===========================================================================
# PART 4 - FINALISE
# ===========================================================================
Add-Line ''
Add-Line '=== END OF COLLECTED DATA ==='
$FullText += "`r`n`r`n" + '=== END OF COLLECTED DATA ===' + "`r`n"

[System.IO.File]::WriteAllText($ReportPath, $FullText, [System.Text.UTF8Encoding]::new($false))

$Elapsed = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)
$SizeKB  = [math]::Round((Get-Item $ReportPath).Length / 1KB, 1)

Write-Host ""
Write-Host "Done in $Elapsed seconds." -ForegroundColor Green
Write-Host "Report: $ReportPath  ($SizeKB KB)" -ForegroundColor Green
if (-not $ComOk) {
    Write-Host ""
    Write-Host "NOTE: Outlook was not running (or COM attach failed), so accounts, data files," -ForegroundColor Yellow
    Write-Host "      add-ins and folder counts were skipped. Open Outlook and re-run for full results." -ForegroundColor Yellow
}
Write-Host ""

try { Start-Process explorer.exe "/select,`"$ReportPath`"" } catch { }
