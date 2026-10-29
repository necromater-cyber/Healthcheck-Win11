<#
.SYNOPSIS
    Authenticode-signs HealthCheck.exe, timestamps it, verifies the result and refreshes the .sha256 file.

.DESCRIPTION
    Run this on a Windows machine that has your code-signing certificate. It does not create trust by
    itself: the certificate must chain to a CA that the target machines trust (public CA, or your
    enterprise CA distributed by Group Policy / Intune).

.EXAMPLE
    # Certificate in the current user's store (smart card / token / HSM-backed certs work this way):
    .\Sign-HealthCheck.ps1 -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567

.EXAMPLE
    # Certificate in a PFX file (you will be prompted for the password):
    .\Sign-HealthCheck.ps1 -PfxPath C:\Secure\codesign.pfx

.EXAMPLE
    # Lab only: create and use a self-signed certificate (trusted ONLY on machines where you import it)
    .\Sign-HealthCheck.ps1 -CreateSelfSigned
#>
[CmdletBinding(DefaultParameterSetName = 'Store')]
param(
    [string]$ExePath = (Join-Path $PSScriptRoot 'HealthCheck.exe'),
    [Parameter(ParameterSetName = 'Store')][string]$Thumbprint,
    [Parameter(ParameterSetName = 'Pfx', Mandatory)][string]$PfxPath,
    [Parameter(ParameterSetName = 'Self')][switch]$CreateSelfSigned,
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [string]$Subject = 'CN=HealthCheck (self-signed lab certificate)'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $ExePath)) { throw "Not found: $ExePath" }

# --- locate the certificate ------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Pfx') {
    $pw = Read-Host 'PFX password' -AsSecureString
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $PfxPath, $pw, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
}
elseif ($CreateSelfSigned) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
    Write-Host "Created self-signed certificate $($cert.Thumbprint)." -ForegroundColor Yellow
    Write-Host 'It is trusted only where you import it into Trusted Root AND Trusted Publishers.' -ForegroundColor Yellow
}
else {
    $candidates = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert |
        Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) }
    $cert = if ($Thumbprint) { $candidates | Where-Object Thumbprint -eq ($Thumbprint -replace '\s', '') | Select-Object -First 1 }
            else { $candidates | Sort-Object NotAfter -Descending | Select-Object -First 1 }
    if (-not $cert) { throw 'No valid code-signing certificate with a private key was found. Pass -Thumbprint or -PfxPath.' }
}
Write-Host "Signing with: $($cert.Subject)  [$($cert.Thumbprint)]  expires $($cert.NotAfter.ToString('yyyy-MM-dd'))"

# --- sign + timestamp ------------------------------------------------------------------------
# The timestamp keeps the signature valid after the certificate itself expires.
$sig = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -HashAlgorithm SHA256 `
    -TimestampServer $TimestampServer -IncludeChain NotRoot
if ($sig.Status -notin 'Valid', 'UnknownError') { throw "Signing failed: $($sig.Status) - $($sig.StatusMessage)" }

# --- verify ----------------------------------------------------------------------------------
$check = Get-AuthenticodeSignature -FilePath $ExePath
Write-Host ''
Write-Host "Status      : $($check.Status)"
Write-Host "Signer      : $($check.SignerCertificate.Subject)"
Write-Host "Timestamped : $(if ($check.TimeStamperCertificate) { $check.TimeStamperCertificate.Subject } else { 'NO - re-run with a reachable -TimestampServer' })"
if ($check.Status -eq 'UnknownError' -or $check.Status -eq 'NotTrusted') {
    Write-Host 'Signature is present but this machine does not trust the certificate chain (expected for self-signed).' -ForegroundColor Yellow
}

# --- the hash changes when a file is signed, so refresh the published checksum ----------------
$hash = (Get-FileHash -Algorithm SHA256 -Path $ExePath).Hash.ToLower()
Set-Content -Path "$ExePath.sha256" -Value "$hash  $(Split-Path $ExePath -Leaf)" -Encoding ascii
Write-Host "SHA-256 (signed file): $hash"
