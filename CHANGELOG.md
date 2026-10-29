# Changelog

## 1.3.0 - 2026-10-29
- Started as Administrator and chose the Outlook check (or "Both")? The launcher now explains that an
  elevated window cannot reach Outlook and offers to open the Outlook check in a normal window.
- Windows collector 2.5: reads Microsoft Defender exclusions when elevated, flags exclusions that are
  broad (a whole drive, all of C:\Users) and reports whether Outlook or its data files are excluded.
- Outlook collector 1.3: new-Outlook (olk.exe) detection, TCP 443 connect timing to the Microsoft 365
  mail endpoints, and "unknown" instead of a false "none" when exclusions cannot be read.
- Fixed PowerShell comparison coercion that produced false "unavailable" and false CRITICAL results.
- Copilot preset limits output to three files.

## 1.2.x
- Polished console UI (no dependencies), version shown in the UI, script-extraction option removed
  because the scripts are now published in this repository.
