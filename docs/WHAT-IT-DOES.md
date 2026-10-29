# What HealthCheck does to a machine

This page lists everything the tool runs, writes and connects to, so it can be checked against the code.
Where a line number is given it refers to the files in this repository at the time of writing; use search if
the code has moved.

## 1. What the launcher (HealthCheck.exe) does
| Action | Why | Code |
| --- | --- | --- |
| Writes the embedded script to a private temp folder (`%TEMP%\healthcheck-*`), runs it, deletes the folder on exit | The scripts are embedded in the exe | `runScript` in `main.go` |
| Starts `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <temp script>` | Runs the collector. Bypass is needed because the script is unsigned | `runScript` in `main.go` |
| Asks Windows to show a UAC prompt and relaunches itself elevated (only when you choose the Windows check and accept) | The Windows check needs Administrator for SMART, TPM, BitLocker, Security log | `relaunchElevated`, `platform_windows.go` |
| Opens a normal (non-elevated) window with `runas.exe /trustlevel:0x20000` (only when started elevated and you choose the Outlook check) | Outlook automation does not work from an elevated process | `relaunchUnelevated`, `platform_windows.go` |
| Runs `tasklist` to see whether `OUTLOOK.EXE` or `olk.exe` is running | Advises you before the Outlook check | `processRunning`, `platform_windows.go` |
| Sets the console to UTF-8 and enables colour; sets the window title | Display only | `initUI`, `enableVT` |
| Sets the environment variable `HEALTHCHECK_LAUNCHER` for the child process | Records the launcher version in the report header | `main` in `main.go` |

The launcher imports no networking package and makes no network connections of its own.

**Redaction (only with `--redact` or when you answer yes in the menu).** After the collector finishes, `redact.go`
reads the report files it just wrote, writes redacted copies (renaming files that contain the host name), deletes
the unredacted originals, and writes `DO-NOT-UPLOAD_redaction-map_<timestamp>.txt` next to them. It reads the
environment variables `COMPUTERNAME`, `USERNAME`, `USERDOMAIN`, `USERDNSDOMAIN` and `USERPROFILE` to know what to
replace. See [REDACTION.md](REDACTION.md).

## 2. External programs the Windows collector runs (all read-only)
| Command | Purpose |
| --- | --- |
| `powercfg /list`, `/query`, `/availablesleepstates`, `/devicequery wake_armed`, `/lastwake` | Power and sleep configuration |
| `powercfg /batteryreport /output <file>` | Battery report, only with `-IncludeBatteryReport`; writes one HTML file |
| `reagentc /info` | Windows Recovery Environment status |
| `vssadmin list shadowstorage` | Shadow copy storage (read-only listing) |
| `fltmc filters`, `fltmc instances` | File system minifilters (needs elevation) |
| `netsh wfp show state file=<temp>` | Windows Filtering Platform state. The temp file is deleted afterwards |
| `netsh winsock show catalog`, `netsh int <ipv4/ipv6> show dynamicport <tcp/udp>`, `netsh int tcp show global`, `netsh winhttp show proxy` | Network configuration (all `show`) |
| `DISM.exe /Online /Cleanup-Image /CheckHealth` and `/ScanHealth`, `sfc.exe /VERIFYONLY` | Only with `-IncludeIntegrityScan`. Scan and verify only, no repair |

The rest is PowerShell cmdlets that read: `Get-CimInstance`, `Get-WinEvent`, `Get-MpComputerStatus`,
`Get-MpPreference`, `Get-Service`, `Get-ScheduledTask`, `Get-PhysicalDisk`, `Get-NetAdapter`,
registry reads under `HKLM:` and `HKCU:`, and similar. To check for anything that changes state, search the scripts:

```powershell
Select-String -Path .\scripts\*.ps1 -Pattern 'Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Set-MpPreference|Add-MpPreference|Start-Service|Stop-Service|Restart-Service|Set-Service|Enable-|Disable-|Install-|Uninstall-|Invoke-Expression|FromBase64String|EncodedCommand|Start-Process|Remove-Item|New-Item|Out-File|Set-Content'
```

At the time of writing this finds exactly six lines, all benign:

| Match | What it is |
| --- | --- |
| `New-Item -ItemType Directory` (both scripts) | Creates the output folder if it does not exist |
| `Remove-Item $wfpFile` (Windows script) | Deletes the script's own temporary WFP dump |
| `Start-Process explorer.exe "/select,<report>"` (both scripts) | Shows the finished report in Explorer |
| `Start-Process ... -Verb RunAs` (Windows script) | When run directly and not elevated, offers to relaunch itself elevated. It asks first (`Relaunch as Administrator? (Y/N)`) |

## 3. External programs the Outlook collector runs
Only `netsh.exe` (a read-only `show` command). Everything else is PowerShell reading the registry, files
and Outlook's automation interface. It reads folder item counts, account and add-in names, and data-file
paths and sizes. It does not read message bodies or mail contents.

## 4. Files written
| File | Where | Notes |
| --- | --- | --- |
| `HealthReport_<host>_<timestamp>.md`, or `..._part1of3.md` etc. when split | Desktop or `--out DIR` | The Windows report |
| `OutlookHealthReport_<host>_<timestamp>.md` | Desktop or `--out DIR` | The report |
| `BatteryReport_<host>_<timestamp>.html` | Same folder | Only with `-IncludeBatteryReport` |
| `DO-NOT-UPLOAD_redaction-map_<timestamp>.txt` | Same folder | Only with redaction. Lists the real values behind the placeholders; keep it private |
| Temp copies of the script and the WFP dump | `%TEMP%` | Deleted when the run ends |

Nothing is written to the registry. Nothing is installed.

## 5. Network connections
| Destination | Test | Check |
| --- | --- | --- |
| `8.8.8.8`, `1.1.1.1` | 3 ICMP pings | Windows script, `Test-Connection` |
| `www.microsoft.com:443` | TCP connect | Windows script, `Test-NetConnection` |
| `outlook.office365.com:443`, `outlook.office.com:443`, `outlook.live.com:443` | 3 timed TCP connects each | Outlook script |
| Any host you pass with `--endpoint HOST` | TCP connect to 443 | Outlook script |

These are reachability and timing tests. No report data is sent. DNS lookups for those names happen as a
side effect.

## 6. What the reports contain (so you know what to review)
Hostname, usernames, serial numbers, IP and MAC addresses, installed software, driver names and dates,
local administrator group members, file paths, parts of event-log messages, Outlook account names, add-in
names and data-file paths. Review a report before sharing it.

## 7. What it deliberately does not do
No downloads, no uploads, no persistence (no scheduled task, service or Run key), no registry writes, no
changes to Defender, firewall, updates or drivers, no credential access, no `Invoke-Expression`, no encoded
commands, no obfuscation.
