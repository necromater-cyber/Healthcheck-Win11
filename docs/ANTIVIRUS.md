# Antivirus and SmartScreen warnings

HealthCheck is a small, unsigned program that embeds PowerShell, runs PowerShell with
`-ExecutionPolicy Bypass`, and can relaunch itself elevated. Generic machine-learning detections (for example
Microsoft Defender's `Trojan:Script/Wacatac.C!ml`) score that combination as suspicious. They are heuristic
verdicts, not matches against known malware, and they are a recognised cause of false positives for admin tools.

## What to do
1. Verify the file ([VERIFY.md](VERIFY.md)): hash, provenance, and optionally build it yourself.
2. Read the scripts. They are in this repository.
3. Submit the file to the vendor as a false positive. For Microsoft Defender:
   https://www.microsoft.com/wdsi/filesubmission (choose "Software developer").
4. In a managed environment, ask IT to allow-list the signed exe by certificate, or to allow the scripts.
5. If you must use an exclusion, exclude the single file path, never a folder or drive, and only after step 1.

## Ways to avoid the warning entirely
- Run the scripts directly (README option 1). Plain `.ps1` files are scored differently from an exe.
- Use a release signed with a certificate your organisation trusts (`tools/Sign-HealthCheck.ps1`).
- Build from source in your own pipeline and sign with your own certificate.

## Detection history
Record each report here (date, version, vendor, verdict, submission ID, outcome) so users can see it was handled.

| Date | Version | Vendor | Verdict | Outcome |
| --- | --- | --- | --- | --- |
| 2026-10-27 | 1.3.0 | Microsoft Defender | Trojan:Script/Wacatac.C!ml | Submission pending |
