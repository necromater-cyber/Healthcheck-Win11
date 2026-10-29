# Security policy

## Reporting a vulnerability or a trust concern
Please use GitHub's private "Report a vulnerability" option on this repository's Security tab. If that is
not available, open an issue titled "Security contact request" without details and the maintainer will
arrange a private channel. Expect an acknowledgement within a few days.

Examples worth reporting: a command the tool runs that can change system state, an unexpected network
connection, a way for report contents to execute code, or a release file whose hash does not match the one
published here.

## Design commitments
- **Read-only.** The scripts query system state. They do not set, install, repair, enable, disable or
  delete anything on the machine other than their own temporary files. `docs/WHAT-IT-DOES.md` lists every
  external command so this can be audited.
- **No uploads, no telemetry.** The tool never sends report data anywhere. It makes only the connectivity
  tests listed in `docs/WHAT-IT-DOES.md`.
- **No hidden code.** There is no obfuscation, no encoded commands, no downloaded code and no
  `Invoke-Expression`. The embedded scripts are byte-for-byte the files in `scripts/`; the exe prints their
  SHA-256 with `HealthCheck version`.
- **Reproducible provenance.** Releases are built by the workflow in `.github/workflows/release.yml` and
  carry a SHA-256 file and a build provenance attestation.

## Known limits
- The launcher runs the scripts with `-ExecutionPolicy Bypass` because the scripts are unsigned. In an
  environment that blocks this (AppLocker, WDAC, Constrained Language Mode) the run fails with a message.
- Reports contain identifying details. Review before sharing.

## Supported versions
Only the latest release is supported.
