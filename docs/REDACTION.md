# Redaction

`--redact` (or answering **yes** to "Redact identifying details?" in the menu) replaces identifying details in
the finished report files with placeholders, so the report is safer to share with an outside AI service.

It is a **best-effort safety net, not a guarantee**. Read the report before you share it.

## How it works
- It runs in the launcher (`redact.go`) after the collector has written its report. The PowerShell scripts are
  unchanged and still produce the full report if you run them directly.
- Each real value becomes the same placeholder everywhere in the run (every part of a split report), so an AI can
  still follow "IP-PRIV-2 is the DNS server on adapter X".
- The first file of the run gets a note telling the AI that placeholders are ordinary names, not anomalies.
- Files whose names contain the host name are renamed (`HealthReport_HOST-1_...`), and the original is removed only
  after the redacted copy has been written.
- A map from placeholders back to real values is saved as `DO-NOT-UPLOAD_redaction-map_<timestamp>.txt` in the
  same folder. Keep it private. It is the only place the real values remain.

## What is replaced
| Placeholder | What | Notes |
| --- | --- | --- |
| `HOST-n` | This computer's name | Anywhere in the text and in file names |
| `USER-n` | This user's name, and any other profile folder under `C:\Users` | `Public`, `Default`, `All Users` and `Administrator` are kept. Common words ("User", "Admin") are replaced only in profile paths and `DOMAIN\name` pairs, never in ordinary sentences |
| `DOMAIN-n`, `DNSDOMAIN-n` | The user's domain and DNS domain | |
| `EMAIL-n` | E-mail addresses | Includes Outlook account names |
| `SID-n` | Account-domain SIDs (`S-1-5-21-...`) | The trailing RID stays (500 is the built-in Administrator). Well-known SIDs stay |
| `IP-PRIV-n`, `IP-PUB-n`, `IPV6-n` | IPv4 and IPv6 addresses | See below |
| `MAC-n` | MAC addresses | |
| `SERIAL-n` | Serial numbers, UUIDs and machine GUIDs | "List" lines (`SerialNumber : ...`) and Format-Table columns under a `SerialNumber` header. Firmware placeholders such as "To be filled by O.E.M." and all-zero values are kept |
| `ORG-n` | The organisation in `OneDrive - <organisation>` paths | |

### IP address rules
- Private (RFC 1918) and link-local addresses are always replaced.
- Public addresses are replaced only on lines that are about the network (address, DNS, gateway, resolved,
  connect...), so software and driver version numbers such as `1.0.2.1` are not mistaken for addresses.
- Lines that mention a version, build, driver or firmware, or that carry a date, are left alone.
- Left unchanged: masks (`255.x`), loopback, `0.0.0.0`, multicast, and well-known public resolvers
  (8.8.8.8, 1.1.1.1, 9.9.9.9 and the like), which are not identifying and are used by the tool's own tests.

## What it does not catch
- Names in free text: other users' names (unless they have a profile folder), colleagues, customers, project or
  file names, mailbox display names and folder names.
- Installed software that reveals your employer, and company names in device names or certificate subjects.
- Machine names of other computers on your network.
- The battery report (`BatteryReport_*.html`), which is not processed.
- Anything in a report you did not run through `--redact`.

Skim the report for these before you upload it. The summary printed after a run says how many of each kind of
value were replaced.

## Trade-offs
Redaction removes information an analyst might use: real addresses, serials and names. The map file lets you
translate findings back. Leave redaction off when the report stays inside your organisation or goes only to an
approved internal AI service.

## Checking it yourself
`redact_test.go` has the rules as tests. To run the redactor against your own report files without committing
them:

```
REDACT_SAMPLE_DIR=/path/to/reports REDACT_HOST=MYPC REDACT_USER=myuser go test -run TestRedactSamples -v
```
