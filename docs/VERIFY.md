# Verifying a download

## 1. Check the hash
Each release publishes `SHA256SUMS.txt` (the exe and both scripts). On Windows:

```powershell
Get-FileHash .\HealthCheck.exe -Algorithm SHA256
```

The value must match the release's `SHA256SUMS.txt`. If the exe was code-signed, the hash of the signed file is
published instead; the release notes say which.

## 2. Check the embedded scripts match the repository
```
HealthCheck.exe version
```
prints the SHA-256 of each embedded script. Compare with:

```powershell
Get-FileHash .\scripts\Get-Windows11HealthReport.ps1, .\scripts\Get-OutlookHealthReport.ps1 -Algorithm SHA256
```

(Take the scripts from the same release tag.) Matching hashes mean the exe contains exactly the code you can read here.

## 3. Check the build provenance
Release files are built by GitHub Actions and attested. With the GitHub CLI:

```
gh attestation verify HealthCheck.exe --repo necromater-cyber/Healthcheck-Win11
```

This proves the file was produced by this repository's release workflow from the tagged commit.

## 4. Check the signature, if signed
```powershell
Get-AuthenticodeSignature .\HealthCheck.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

## 5. Or build it yourself
See [BUILDING.md](BUILDING.md). `go build -trimpath` with the flags shown there produces a binary whose
behaviour you can compare against the release.

## A reviewer's checklist (about 20 minutes)
1. Read [WHAT-IT-DOES.md](WHAT-IT-DOES.md).
2. Run the `Select-String` command in section 2 of that page and confirm there are no mutating cmdlets.
3. Search the Go source for network use: `Select-String -Path *.go -Pattern 'net/http|net\.Dial|http\.'` finds nothing.
4. Read `runScript` in `main.go`: it writes a script, runs PowerShell on it, deletes the folder.
5. Read the section headers in each script; each `Add-Section` has a plain-English purpose.
6. Run the scripts directly (README, option 1) in a test VM before deploying the exe.
