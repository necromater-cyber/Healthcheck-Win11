# Technical Explainer: Get-Windows11HealthReport.ps1

**What this document is:** a section-by-section reference for what the collector script tests, which Windows APIs and event sources it queries, and why each check exists. Pair it with the script itself — this explains *what* and *why*; the script's inline `-Purpose` strings are the condensed version the AI assistant reads at analysis time.

**Version covered:** 2.1 (37 collection sections, digest, verbosity/splitting, Fast-Startup-aware uptime reconciliation, restart cadence policy).

---

## 1. How the script is structured

Four phases, in order:

1. **Elevation check** — detects whether it's running as Administrator and offers to relaunch if not. Several checks (SMART counters, TPM, BitLocker, the Security log, minifilter enumeration) silently degrade or report "unavailable" without elevation rather than failing the whole run.
2. **Collection** — 37 numbered sections, each wrapped in `Add-Section`, which captures output, catches errors per-section so one failure doesn't abort the run, and truncates long messages according to the chosen verbosity level.
3. **Triage digest** — after all sections run, ~40 metrics are recomputed independently and assembled into a flagged summary table (`OK` / `WATCH` / `ACTION` / `ACTION - CRITICAL`) placed at the top of the file, above the raw evidence.
4. **Finalise** — the AI analysis prompt, the digest, and all section output are assembled into one Markdown document (or split into multiple parts if it exceeds a size limit) and written to disk.

Everything is designed around one constraint: **the file is meant to be read by an AI assistant with a limited context window**, so the same fact is often surfaced twice — once as a pre-computed, flagged metric in the digest, and once as raw evidence in its full section — so a truncated upload still carries the analytical conclusion even if the supporting detail is cut off.

---

## 2. The digest: pre-computed triage metrics

Before explaining each section, it's worth explaining the digest, because it changes how the rest of the file should be read.

Each digest metric is produced by `New-Metric`, which runs a small script block, catches any failure and reports `unavailable` instead of crashing the whole digest, and — if given an assessment block — assigns a flag by evaluating the computed value against a threshold. Roughly 30 metrics are computed this way, covering:

- Free space, disk health, SMART error counters
- Bugcheck / Kernel-Power 41 / dirty shutdown counts
- Pending reboot state, days since last dated hotfix
- Defender real-time protection, signature age, full-scan age
- Secure Boot, TPM readiness, BitLocker protection status
- Minifilter counts (registered vs. loaded), orphaned filter registrations, anti-virus band occupancy
- Non-Microsoft Winsock providers, default route count, TCP connection count, port-exhaustion warning count
- **Reconciled uptime** and **restart cadence compliance** (see §4 below)

The digest is intentionally **not** a replacement for the raw sections — it's a fallback. The report header tells the AI: if the raw evidence is truncated, treat the digest as authoritative and say so, rather than refusing to analyse.

---

## 3. Section-by-section reference

### Identity, hardware and storage baseline (01–06)

| § | What it queries | What it's checking for |
|---|---|---|
| **01. Operating System & Identity** | `Win32_OperatingSystem`, `Win32_ComputerSystem`, `HKLM\...\CurrentVersion` | Build number, edition, install date, domain membership, RAM/CPU counts. Also records Fast Startup (`HiberbootEnabled`) state here — see §4. |
| **02. Hardware Summary** | `Win32_Processor`, `Win32_BIOS`, `Win32_BaseBoard`, `Win32_PhysicalMemory`, `Win32_VideoController` | CPU model/cores, BIOS/UEFI version and release date, per-DIMM speed and part number, GPU driver version and date. An old BIOS date is a common instability root cause on desktops. |
| **03. Volumes & Free Space** | `Get-Volume` | Free space percentage per drive letter. Under ~15% degrades Windows Update, VSS and defrag; under 10% is treated as a HIGH finding. |
| **04. Physical Disk Health & SMART** | `Get-PhysicalDisk`, `Get-StorageReliabilityCounter`, `Win32_DiskDrive` | `HealthStatus`, temperature, power-on hours, SSD wear percentage, and — critically — `ReadErrorsUncorrected` / `WriteErrorsUncorrected`. Any non-zero uncorrected error count is treated as a hardware fault, not something software remediation can fix. **Known limitation:** NVMe drives (including the Samsung 980 PRO class of device) often report these counters as blank; `Get-StorageReliabilityCounter` doesn't expose the full NVMe SMART log, so a clean-looking result here doesn't fully rule out media wear on NVMe. |
| **05. Storage & Filesystem Error Events** | `Get-WinEvent` against `disk`, `Ntfs`, `volmgr`, `volsnap`, `storahci`, `stornvme`, `partmgr` providers | Controller timeouts, filesystem corruption, and Volume Shadow Copy failures (the `volsnap` provider is what caught the "shadow copies aborted, disk full" chain in earlier runs of this tool). |
| **06. Memory Diagnostic Results** | `Microsoft-Windows-MemoryDiagnostics-Results` provider, 365-day window | Whether Windows Memory Diagnostic (`mdsched.exe`) has ever run and what it found. Absence of results isn't a fault by itself — it's a note that RAM has never been tested. |

### Stability and crash history (07–12)

This is the most heavily cross-referenced block — bugcheck evidence here is what every other section's driver/hardware/update findings get checked against.

| § | What it queries | What it's checking for |
|---|---|---|
| **07. Crashes, Bugchecks & Unexpected Shutdowns** | Event IDs 41 (`Kernel-Power`), 1001 (`WER-SystemErrorReporting`), 6008 (dirty shutdown), 1074/1076/6005/6006 (shutdown/restart reasons); crash dump files on disk; `Win32_OSRecoveryConfiguration` | The core stability signal. Kernel-Power 41 means the machine lost power or hard-hung without a clean shutdown sequence; 1001 carries the actual blue-screen stop code. **This section also contains the Fast-Startup-aware boot/uptime reconciliation and the restart cadence policy check — see §4 and §5 below**, because they logically belong with "how has this machine actually been power-cycled," not with raw OS identity. |
| **08. Application Crashes & Hangs (WER)** | Event IDs 1000/1001/1002/1026 in the Application log | User-mode crashes (1000), hangs (1002), and .NET runtime failures (1026). Repeated faults in the *same faulting module* across different applications point to a shared driver, codec, or security product rather than independent app bugs — the collector doesn't compute this correlation itself, but structures the frequency table so the pattern is visible. |
| **09/10. System Log — Errors / Warnings** | `Get-WinEvent -Level 1,2` and `-Level 3` against the System log | The general-purpose error/warning feed. Grouped by provider+EventID with first/last-seen timestamps so genuinely chronic issues (400 occurrences) are distinguishable from one-off noise (1 occurrence) at a glance. |
| **11. Application Log — Errors** | Same, against the Application log | Application-tier equivalent of §09. |
| **12. Reliability Monitor History** | `Win32_ReliabilityRecords` (the same data behind `perfmon /rel`) | A independent second opinion on stability, useful for spotting a date where reliability visibly changed — often traceable to a specific software install. |

### Boot performance and live snapshot (13–14)

| § | What it queries | What it's checking for |
|---|---|---|
| **13. Boot & Shutdown Performance** | `Microsoft-Windows-Diagnostics-Performance/Operational` log, IDs 100 (boot), 101–110 (degradation contributors), 200–203 (shutdown) | Actual measured boot duration in milliseconds, plus which specific process or driver Windows itself attributed the slowdown to. Windows tags each boot with `IsDegradation: true/false` — the collector surfaces this so a slow boot caused by a one-time update installation isn't confused with a systemic regression. |
| **14. Live Performance Snapshot** | `Win32_OperatingSystem` memory counters, `Win32_PageFileUsage`, `Get-Counter` (5×1s CPU sample), `Get-Process` | A point-in-time-only sample: memory pressure, page file usage, CPU load, and the top 15 processes by working set and by CPU time. **Also identifies the single process holding the most handles** and, if it's `svchost`, enumerates which services that particular `svchost` instance is hosting — this is what turns "some svchost has 200,000 handles" into "which service is leaking." |

### Devices and drivers (15–17)

| § | What it queries | What it's checking for |
|---|---|---|
| **15. Problem Devices** | `Win32_PnPEntity` filtered to `ConfigManagerErrorCode <> 0` | Any device Device Manager considers broken. Code 28 = missing driver, 43 = device reported its own failure, 10 = cannot start. |
| **16. Third-Party Drivers** | `Win32_PnPSignedDriver`, filtered to non-Microsoft providers | Driver age and version for everything not shipped in-box. Drivers older than ~3 years, or ones installed right before instability began, are the first suspects when cross-referenced against §07's bugcheck dates. |
| **17. Driver / Kernel Load Events** | `Kernel-PnP`, `DriverFrameworks-UserMode`, `Display`, and vendor GPU providers (`nvlddmkm`, `amdkmdag`) | GPU driver timeout/reset (TDR) events and kernel-mode driver load failures. |

### Servicing (18–20)

| § | What it queries | What it's checking for |
|---|---|---|
| **18. Windows Update — Installed Hotfixes** | `Get-HotFix` | Full patch history. **Handles a known WMI quirk:** hotfixes with a null `InstalledOn` (staged but not finalised) used to crash the sort; the collector now reports these as `PENDING / no date`, computes days-since-last-*dated* update separately, and counts undated entries so a pending update doesn't silently disappear from the report. A gap over ~45 days is treated as a security-relevant finding. |
| **19. Windows Update Client Activity & Failures** | `Microsoft-Windows-WindowsUpdateClient` provider; the `Setup` log | Update installation attempts and failures. Repeated failure of the same KB points at component-store corruption rather than a transient network issue. |
| **20. Pending Reboot Indicators** | Four independent registry/state checks: CBS `RebootPending`, WU `RebootRequired`, `PendingFileRenameOperations`, and a computer-rename-pending comparison | Whether servicing is mid-transaction. Any of these being `True` explains "Windows Update keeps failing" far more often than actual corruption does. |

### Services, tasks and startup (21–24)

| § | What it queries | What it's checking for |
|---|---|---|
| **21. Services — Automatic but Not Running** | `Win32_Service` filtered to `StartMode = Auto`, `State != Running` | A raw list — deliberately not treated as a hard fault by itself, since many modern services are trigger-start and legitimately sit stopped until needed. |
| **22. Service Control Manager Failures** | Event IDs 7000/7001/7009/7011/7023/7024/7031/7034 | Start failures, timeouts, unexpected termination, dependency failures — the event-log evidence that corroborates §21. |
| **23. Scheduled Tasks — Non-Zero Last Result** | `Get-ScheduledTask` / `Get-ScheduledTaskInfo` across all enabled tasks | Any task whose last run returned a non-zero result code. This is where Storage Sense failures, broken vendor maintenance tasks (e.g. orphaned OEM utility tasks), and failed Defender scan schedules surface. |
| **24. Startup Programs** | `Win32_StartupCommand` | What launches at logon, for correlation against boot-degradation contributors in §13. |

### Network (25, 34, 35)

| § | What it queries | What it's checking for |
|---|---|---|
| **25. Network Configuration & Connectivity** | `Get-NetAdapter`, `Get-NetIPConfiguration`, `Get-NetTCPConnection`, `Test-Connection`, `Test-NetConnection` | Adapter status and link speed, IP/gateway/DNS configuration per interface, a live connection-state summary, and actual reachability tests (ping + a TCP 443 handshake) rather than assuming connectivity from configuration alone. |
| **34. Network Filter Drivers** *(see §7 below for the full filter-stack rationale)* | `Get-NetAdapterBinding -AllBindings`, the NetClient/NetService/NetTrans registry classes, `netsh wfp show state` (parsed from XML), `netsh winsock show catalog` | NDIS lightweight filters, WFP callouts/providers, and Winsock LSPs — the three layers that can intercept or redirect network traffic below the application layer. |
| **35. Network Stack Configuration** | `netsh int tcp/udp show dynamicport`, `Get-NetTCPConnection` grouped by owning process, `netsh int tcp show global`, `Get-NetTCPSetting`, `Get-NetRoute`, `Get-DnsClientServerAddress`, hosts file, proxy settings, firewall block rules | The configuration that explains *why* a filter or exhaustion symptom happens: ephemeral port range, per-process connection counts (identifies what's actually consuming ports), multiple default routes (competing VPN adapters), and manual traffic redirection via hosts file or proxy. |

### Security (26–27)

| § | What it queries | What it's checking for |
|---|---|---|
| **26. Security Posture** | `Get-MpComputerStatus`, `root\SecurityCenter2\AntiVirusProduct`, `Get-MpThreatDetection`, `Get-NetFirewallProfile`, `Get-BitLockerVolume`, `Confirm-SecureBootUEFI`, `Get-Tpm`, `Get-LocalGroupMember` | Defender real-time protection and signature currency, registered AV products, recent threat detections, firewall profile state, disk encryption status, Secure Boot, TPM readiness, and local administrator membership — the full security baseline in one place. |
| **27. Security & Audit Log Highlights** | Event IDs 1102 (log cleared), 4625 (failed logon), 4720/4726/4732/4740 (account changes) — **requires elevation** | Tamper indicators and account-management activity. Skipped cleanly (not silently) without admin rights. |

### Configuration hygiene (28–31)

| § | What it queries | What it's checking for |
|---|---|---|
| **28. Power Configuration** | `powercfg /list`, `/query`, `/availablesleepstates`, `/devicequery wake_armed`, `/lastwake` | Active power scheme, sleep settings, and what last woke the machine — relevant when correlating against Kernel-Power events in §07. |
| **29. Event Log Health & Retention** | `Get-WinEvent -ListLog *` | How large each log is, its configured max size, and — critically — the timestamp of its **oldest surviving record**. This is what exposes when a requested analysis window (e.g. "last 7 days") is actually only backed by 2–4 days of real log data, because a busy log wrapped early. |
| **30. Recently Installed Software** | `HKLM\...\Uninstall` registry keys (both native and WOW6432Node) | Full application inventory with install dates, for correlating the *onset* of instability against what was installed right before it. |
| **31. System Restore & Recovery Readiness** | `Get-ComputerRestorePoint`, `reagentc /info`, `vssadmin list shadowstorage` | Whether a safety net exists before any remediation is attempted. Directly gates how the AI is instructed to phrase destructive recommendations (see §6). |

### Filter driver stacks (32–35)

This block exists because filter drivers are largely invisible to normal troubleshooting — they don't throw errors when working normally, they just add latency or intercept traffic silently, and they're one of the most common things left behind by an incomplete uninstall.

| § | What it queries | What it's checking for |
|---|---|---|
| **32. File System Filter Drivers (minifilters)** | `fltmc filters` / `fltmc instances`, plus a direct registry walk of `HKLM\SYSTEM\CurrentControlSet\Services\*\Instances\*` for the `Altitude` value | Every filter that intercepts file I/O, in load order. The registry walk deliberately covers filters that are *registered but not currently loaded*, which `fltmc` alone won't show. Each filter's altitude is mapped to Microsoft's published load-order bands (e.g. 320000–329999 = Anti-Virus, 140000–149999 = Encryption) so the AI can recognise, for example, two different vendors both claiming the anti-virus band — a real-time-scanning collision. Each filter's binary is also resolved and Authenticode-checked; a registration whose file is missing (`FILE MISSING`) is a direct fingerprint of an incomplete uninstall. |
| **33. Storage & Device Class Filter Drivers** | `UpperFilters`/`LowerFilters` on every entry under `HKLM\SYSTEM\CurrentControlSet\Control\Class`, resolved against their service keys; also `Win32_SystemDriver` for all running non-Microsoft kernel drivers | The legacy (pre-minifilter) filtering mechanism, which sits in the device stack rather than the file-system stack. A class filter naming a driver that no longer has a service key can directly block every device in that class from starting — this is the mechanism most likely to explain a stray Device Manager code 10 elsewhere in the report. |
| **34. Network Filter Drivers (NDIS / WFP / Winsock)** | See the network table above | The three network interception layers: NDIS bindings (per-adapter), WFP callouts and filter counts (parsed from `netsh wfp show state`'s XML output), and the Winsock provider catalog. Non-Microsoft Winsock LSPs are flagged specifically — this is a known persistence mechanism for adware and traffic-interception tools, not just a performance concern. |
| **35. Network Stack Configuration** | See the network table above | Configuration-level traffic redirection: proxy settings, hosts file entries, and DNS server assignment achieve the same effect as a filter driver without one being installed, so they're checked alongside the filter sections rather than treated as unrelated. |

### Optional deep checks (36–37)

| § | Enabled by | What it does |
|---|---|---|
| **36. Component Store & System File Integrity** | `-IncludeIntegrityScan` | Runs `DISM /Online /Cleanup-Image /CheckHealth`, `/ScanHealth`, and `sfc /VERIFYONLY`. Off by default because it adds 5–20 minutes; `/VERIFYONLY` deliberately does not repair anything, so this section is read-only diagnostics even when included. |
| **37. Battery** | `-IncludeBatteryReport` | `Win32_Battery` plus a full `powercfg /batteryreport` HTML export (written as a separate file alongside the main report). |

---

## 4. Why uptime is measured twice (Fast Startup)

Windows 11's Fast Startup ships enabled by default. What it actually does on "shutdown" is hibernate the kernel session (session 0) rather than terminate it — drivers and kernel state are written to `hiberfil.sys`. On the next power-on, the kernel *resumes* from that image instead of cold-booting.

This matters because `Win32_OperatingSystem.LastBootUpTime` is computed from the kernel's tick counter (`Now − Uptime`), and that tick counter survives hibernation. The result: **the WMI-reported uptime silently anchors to the last true cold boot**, and every Fast Startup cycle since is invisible to it — even though the user genuinely restarted the machine in between.

The collector cross-checks this using **Event ID 6005** ("The Event log service was started"), which fires fresh on every power-on because the Event Log service is a user-mode service that genuinely restarts each time — cold boot or Fast Startup resume alike. Section 07 computes:

- `HiberbootEnabled` (registry state)
- WMI `LastBootUpTime` (tick-based, potentially stale)
- The most recent Event 6005 timestamp (true power-on marker)
- The gap between them, with a plain-language verdict

If Fast Startup is on and the two disagree by more than an hour, the report states this is expected behaviour — not a fault — and instructs the AI to use the Event-6005-based figure for any claim about how recently the machine was restarted. If no Event 6005 exists in the 90-day lookback, the report says "unknown" rather than guessing.

---

## 5. Restart cadence policy (`-MaxUptimeDays`)

Built directly on the reconciliation in §4. The script accepts `-MaxUptimeDays` (default 7) as a stated organisational expectation, then:

- Computes the reconciled true uptime (Event 6005-based, not raw WMI)
- Reports compliance as `within policy (Xd of Yd)` or `OVERDUE by Xd — Yx the policy interval`
- Flags `WATCH` at 1–3× the policy interval and `ACTION` beyond 3×
- Ties the overdue state to concrete downstream evidence already present elsewhere in the report: the top handle-holding process in §14 (accumulation over uptime), port-exhaustion warnings in §10/25/35, and pending-reboot/hotfix-age metrics in §18/20 (an overdue restart directly explains an overdue patch)

The AI prompt tiers the severity of this specifically so "the machine hasn't restarted in a while" becomes a scored finding rather than a passing remark, and it explicitly directs the AI toward a *procedural* fix (scheduled restart via maintenance window, GPO, Task Scheduler, or MDM policy) rather than a technical one — and specifically away from "disable Fast Startup," which fixes measurement accuracy, not restart cadence.

---

## 6. Output format and the embedded AI prompt

The finished file is Markdown, structured as:

1. A large **AI analysis prompt** (fixed instructions, not machine-generated) that assigns the assistant a senior-engineer role, defines a five-level severity model (`CRITICAL` → `INFORMATIONAL/NOISE`), and mandates a specific report structure: Executive Summary, Health Scorecard, Findings (with observation/evidence/interpretation/root-cause-confidence/impact), Correlation & Timeline, Recommendations (each requiring justification, a rejected alternative, exact steps, a verification method, and a rollback path), Quick Wins, Watch List, and a Data Gaps & Confidence statement.
2. The **triage digest** (§2 above).
3. All 37 raw evidence sections, each with an inline `-Purpose` note telling the AI what to look for before it sees the data.
4. Collection metadata (elapsed time, verbosity profile, restart cadence policy, sections attempted).

Two behavioural constraints are baked into the prompt worth knowing about:

- **It will not recommend destructive fixes without gating them.** Reinstalls, resets, disk wipes, registry surgery, and driver rollbacks each require the prompt to first list non-destructive diagnostics and confirm a backup/restore-point prerequisite exists (checked against §31).
- **It will not refuse to analyse incomplete data.** Because chat platforms often truncate large uploads, the prompt explicitly distinguishes "don't invent data" (forbidden) from "require every section to be present" (not required) — a missing section goes into the Data Gaps section with reduced confidence, not into a refusal.

---

## 7. Practical controls

| Parameter | Effect |
|---|---|
| `-DaysBack N` | Event log lookback window (default 7) |
| `-Verbosity Compact\|Standard\|Full` | Caps table row counts, message length, and event detail depth; `Full` restores the WFP per-filter list and complete NDIS binding table that are omitted at lower levels |
| `-SplitOutput` / `-MaxPartKB N` | Splits the report at section boundaries into multiple files sized for chat-assistant upload limits; each part carries a banner (and, from v2.1, an explicit `=== END OF PART n OF m ===` footer) so a receiving AI can detect mid-part truncation instead of inferring it |
| `-MaxUptimeDays N` | The restart cadence policy threshold (§5) |
| `-IncludeIntegrityScan` | Adds DISM/SFC read-only integrity checks (§36) |
| `-IncludeBatteryReport` | Adds the battery section and HTML report (§37) |
| `-OutputFolder` | Destination directory (default: Desktop) |

---

## 8. Known limitations

- **NVMe SMART data is incomplete.** `Get-StorageReliabilityCounter` doesn't expose full NVMe attributes (total lifetime writes, complete media error counters); a "Healthy, 0% wear" result should be read as "nothing Windows's built-in API can see is wrong," not as a complete drive-health certification.
- **Event log retention can silently shrink the analysis window.** If a log wraps before the requested `-DaysBack`, §29 will show the true oldest-record date, but every "first seen" timestamp elsewhere in the report should be checked against it before being treated as an onset date.
- **The digest re-queries the machine independently of the sections.** This means digest metrics can differ trivially in value from their section counterparts if system state changed between queries (normally seconds apart), and it adds roughly 10–20 seconds of runtime.
- **Several checks silently degrade without elevation** (SMART, TPM, BitLocker, Security log, minifilter registry walk) rather than failing the run — the report states elevation status in the header, but a non-admin run should not be read as a clean bill of health on those specific checks.
