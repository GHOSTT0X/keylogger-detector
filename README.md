# Keylogger Detector

A lightweight, defensive tool that hunts for keyloggers and input-capture malware on **Windows 10 / 11**.
It scans running processes, inspects executables for keyboard-hooking APIs, reads the scripts that
interpreters are running, checks Authenticode signatures and looks at startup/persistence locations —
then alerts you through a dark-themed GUI or the command line.

Single file, pure Python, no required dependencies.

> **Defensive use only.** This project detects keyloggers; it does not contain or build one.
> The suspicious samples used by the tests are harmless, generated on the fly and deleted afterwards.

---

## Features

**Process analysis**
- **PE import scanning** — a built-in, pure-Python PE parser reads each executable's import table for
  keyboard-capture APIs (`SetWindowsHookEx`, `GetAsyncKeyState`, `GetKeyboardState`, `GetRawInputData`, …).
- **Dynamic API detection** — finds API names resolved at runtime through `GetProcAddress`.
- **Capability-based scoring** — helper APIs every GUI app uses (`GetKeyState`, `MapVirtualKey`) are not
  enough on their own; polling-only programs (games, macro tools) get a reduced score.
- **Packer & bundle detection** — high-entropy sections with almost no imports, and PyInstaller bundles
  that embed `pynput` / `pyHook` / `pyWinhook`.
- **Masquerading check** — `svchost.exe`, `lsass.exe`, `explorer.exe`, … are only trusted when they run
  from their real system folder.
- **Suspicious locations** — Temp, `Users\Public`, Downloads, Recycle Bin.
- **Network multiplier** — an active outbound connection raises the score, but only on top of a real
  detection signal.

**Script analysis** (`python x.py`, `powershell -File x.ps1`, `wscript`, AutoHotkey, …)
- Detects `pynput`, `keyboard`, `pyHook`, Win32 key-capture calls, `WH_KEYBOARD_LL` and PowerShell
  P/Invoke of `user32`.
- **AST-based de-obfuscation** for Python: catches `__import__('pyn' + 'put')`, `importlib.import_module`,
  `getattr(obj, 'GetAsync' 'KeyState')` and XOR-encoded names.
- Flags exfiltration code (SMTP, `requests.post`, Discord / Telegram webhooks, `Invoke-WebRequest`).
- Encoded PowerShell command lines.

**Signatures**
- Native Authenticode verification through `WinVerifyTrust` (with a PowerShell fallback for
  catalog-signed files).
- A valid signature from a trusted publisher clears binary-only findings; any other valid signature halves
  them. Add publishers with `--trust-publisher`.

**Persistence scanning**
- Run / RunOnce keys (HKCU + HKLM, 32- and 64-bit views), Winlogon `Shell` / `Userinit`, Startup folders
  (including `.lnk` targets), Scheduled Tasks and Services.

**Response**
- Dark SOC-style Tkinter GUI with tabs for suspicious processes, persistence, whitelist and a live event log.
- Desktop pop-up and sound alerts for new detections.
- Safe terminate / delete: the PID and start time are re-checked before acting (PIDs get reused), and
  system / Program Files paths are never deleted.
- **SHA-256 whitelist** — keyed by file hash, not by name or path. For script hosts the command line is
  part of the key, so trusting one Python script never hides another.
- JSONL alert log, continuous monitor mode and optional start at Windows sign-in.

---

## Requirements

- **Windows 10 / 11** (main target). Linux works for lab testing through `/proc`; PE, signature and
  registry checks are Windows-only.
- **Python 3.9+** with Tkinter (included in the standard Windows installer).
- Optional: [`psutil`](https://pypi.org/project/psutil/) for faster, richer process data. Without it the
  tool falls back to native Windows APIs.

```powershell
pip install psutil   # optional
```

Run as **Administrator** for full visibility into other users' and system processes.

---

## Usage

```powershell
python keylogger_detector.py                        # GUI (default)
python keylogger_detector.py --scan                 # one-time CLI scan
python keylogger_detector.py --scan --interactive   # scan, then kill / delete / whitelist findings
python keylogger_detector.py --monitor --interval 5 # continuous CLI monitoring
```

| Option | Description |
|---|---|
| `--gui` | Launch the graphical interface (default). |
| `--viewer` | Open the GUI without starting another monitor. |
| `--scan` | Run a one-time deep scan in the terminal. |
| `--interactive` | After `--scan`, prompt to delete / kill / whitelist each finding. |
| `--monitor` | Monitor processes continuously in the terminal. |
| `--interval N` | Polling interval in seconds for `--monitor` (default `3.0`). |
| `--log PATH` | Write alerts to a JSONL file. |
| `--whitelist PATH` | Use a custom whitelist file. |
| `--trust-publisher NAME` | Trust an exact certificate CN/O (repeatable). |
| `--no-signature-check` | Skip Authenticode checks (faster, more false positives). |
| `--protected-storage` | Keep logs and whitelist under `ProgramData` (Administrator only). |
| `--behavior-trace PATH` | Read runtime keyboard-API events from an external collector (see below). |
| `--enable-sign-in` / `--disable-sign-in` | Add or remove background monitoring at Windows sign-in. |

Data (whitelist, logs) is stored in `%APPDATA%\KeyloggerDetector` by default.

### Scoring

Each process gets a score from 0 to 100. Processes scoring **35+** are reported:

| Score | Severity |
|---|---|
| 70 – 100 | CRITICAL |
| 50 – 69 | HIGH |
| 35 – 49 | MEDIUM |

### Behavior trace (optional)

`--behavior-trace` reads a JSONL file written by an external API monitor. Each line is one event:

```json
{"pid": 1234, "process_start": 1700000000, "timestamp": 1700000055.2, "api": "GetAsyncKeyState"}
{"pid": 1234, "process_start": 1700000000, "timestamp": 1700000056.0, "api": "SetWindowsHookExW", "hook_id": 13, "thread_id": 0, "success": true}
```

100+ key-state polls in the last 30 seconds, or a successful global keyboard hook (`WH_KEYBOARD` /
`WH_KEYBOARD_LL`), adds to that process's score.

---

## Running the tests

```powershell
python -m unittest test_detector
```

`test_live_process_scan` starts real (harmless) Python processes and runs a full scan, so it can take
several minutes. To run only the fast unit tests:

```powershell
python -m unittest -k test_script_patterns -k test_xor -k test_process_scan -k test_behavior -k test_explorer -k test_register -k test_alert -k test_rescan test_detector
```

---

## Limitations

This is a heuristic, user-mode scanner — a helpful extra layer, not a replacement for antivirus / EDR.
It will not catch:

- kernel-mode (driver) keyloggers or hardware keyloggers,
- code injected into a trusted, signed process,
- malware that calls system calls directly or hides its API names in ways the heuristics don't recognize,
- runtime behavior, unless you supply a `--behavior-trace` collector.

False positives are possible (automation tools, games, accessibility software). Review a finding before
deleting anything, and use the whitelist for software you trust.
