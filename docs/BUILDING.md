# Building HealthCheck.exe

Requires Go 1.24 or newer. There are no third-party modules (`go.mod` has no `require` lines).

```
go test ./...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags "-s -w -X main.version=1.4.0 -X main.buildDate=YYYY-MM-DD" -o HealthCheck.exe .
```

On Linux or macOS: `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ...` with the same flags.

The `.ps1` files in `scripts/` are embedded at build time. Edit them, rebuild, and the new version ships in the
exe. `HealthCheck.exe version` prints the SHA-256 of each embedded script.

To compare with a release, build with the release's `version` and `buildDate` values (shown by
`HealthCheck.exe version`). Differences in Go toolchain version will change the bytes; the release notes record
the toolchain used.

## Console UI
Standard library only. Colour, box drawing and the progress bar switch on only when stdout is a console that
accepts ANSI sequences, and switch off when output is redirected, when `NO_COLOR` is set, when `TERM=dumb`,
or when `HEALTHCHECK_PLAIN=1`.

## Signing
`tools/Sign-HealthCheck.ps1` signs and timestamps the exe, verifies it and rewrites the checksum file.
A signature only builds trust where the certificate chains to a CA the machine trusts.
