# KABOOM (Windows Drive Wiper)

> Danger: This tool irreversibly destroys data on the chosen drive. Use at your own risk. Double‑check the target drive letter and run only if you understand the consequences.

## Overview
KABOOM is a Windows‑only, command‑line drive wiping utility. It performs multiple cycles of:
- Reformatting the selected volume to a chosen filesystem (NTFS/exFAT/FAT32)
- Filling the drive with random data via temporary files (single or multi‑threaded)
- Overwriting the beginning (header) of the raw volume to damage filesystem metadata
- Optionally issuing TRIM for SSDs to reduce recoverability

It requires administrative privileges.

## Features
- Multi‑cycle wipe (Low/Medium/High security options)
- Random data fill with large buffers for speed
- Parallel fill (when threads are available)
- Header/metadata overwrite (first N bytes, configurable)
- SSD detection (seek penalty heuristic) and optional TRIM
- Progress bar for long operations

## Requirements
- Windows (tested with modern Windows versions)
- Administrator privileges (formatting, volume lock/dismount)
- `format` and `defrag` available in PATH (Windows built‑ins)
- C++17 compiler to build (MSVC recommended)

## Build
Use a "Developer Command Prompt for VS" or "Developer PowerShell for VS" so `cl` is available.

```powershell
# From the folder containing KABOOM.cpp
cl /std:c++17 /O2 KABOOM.cpp /Fe:KABOOM.exe
```

MinGW (if you prefer):
```powershell
# Adjust path to your g++ and ensure WinAPI headers are installed
g++ -std=c++17 -O2 KABOOM.cpp -o KABOOM.exe
```

No special libraries are needed beyond the Windows SDK that ships with Visual Studio / Build Tools.

## Usage
Run from an elevated PowerShell/Command Prompt. You will be prompted for:
- Wipe method (1–3 cycles)
- Target filesystem (NTFS/exFAT/FAT32)
- Drive letter to wipe (e.g., D)
- Final confirmation (type `YES`)

You can also provide optional flags:

```powershell
KABOOM.exe [options]

Options:
  --simulate            Dry run (skip format/header/trim). Safe preview.
  --force-system        Allow wiping the system drive (dangerous; off by default)
  --header-bytes=N      Bytes to overwrite at the start of the raw volume (default 1048576)
  --no-trim             Skip issuing TRIM after completion (useful for HDDs)
  --help                Show help
```

### Example
```powershell
# High security (3 cycles), format to NTFS, wipe drive E:
# You will be asked to type YES before it proceeds.
KABOOM.exe
```

## What Happens During a Cycle
1. Format the target drive to your chosen filesystem (skipped in `--simulate`).
2. Fill the volume with random data using temporary files until nearly full.
3. Overwrite the first N bytes of the raw volume (default 1 MB) with random data to damage metadata (skipped in `--simulate`).
4. After all cycles, the drive is formatted once more and (if SSD) an optional TRIM is issued unless `--no-trim` is set.

## Notes on Security Levels
- Low (1): One full cycle (format + fill + header overwrite)
- Medium (2): Two cycles
- High (3): Three cycles

The code includes additional routines (wiping existing files, wiping empty space, MFT/header blasting) that are not invoked by default in the main flow. The “High” option currently runs more cycles rather than enabling those extras.

## SSDs vs HDDs
- SSD detection uses a seek‑penalty heuristic; it may misclassify in some cases.
- TRIM is issued at the end on SSDs to mark blocks as free. This is not the same as a cryptographic erase.
- For the strongest SSD sanitization, consider manufacturer secure‑erase tools or standards‑based sanitize commands.

## Safety & Limitations
- Selecting the wrong drive letter will permanently destroy its data.
- Power loss or forced termination can leave the filesystem damaged.
- Overwriting through the filesystem cannot guarantee physical coverage on SSDs due to wear leveling.
- The header overwrite size is configurable; too small may leave recoverable metadata, too large may fail on some configurations.
- The tool is not a certified implementation of specific standards (e.g., DoD 5220.22‑M, NIST 800‑88). Use at your own discretion.

## Troubleshooting
- "Requires administrative privileges": launch an elevated terminal.
- Format failed: ensure the drive is not in use, remove open handles, and verify you have permission. Close Explorer windows on that drive.
- Header wipe lock/dismount failed: another process is holding the volume open.
- Slow performance: reduce cycles, use fewer threads, or verify the device health.

## Development Tips
- `--simulate` is a safer way to preview the flow without destructive operations (note: data fill is skipped in the main destructive steps, but avoid running on important drives regardless).
- Consider refactoring strategies if you plan to enable advanced wipes for the High profile.

## Acknowledgements
- Uses Windows volume APIs and shelling to `format`/`defrag` for formatting and TRIM.

