# OSK4RRV-RAT

**Free Windows information grabber for educational purposes only!**
> Educational project. Use only on systems you own or have explicit permission to test.

## Payload
Our Payload is speacial, grabs all info being undetected and fast.
We provide much functions like Anti-VT Bypass:
<img width="1884" height="703" alt="image" src="https://github.com/user-attachments/assets/043c6fbc-0564-4030-b57d-e0539e4f8cc9" />

---
## Features

### Builder
- Nice GUI - Ideal for begginers.
- Telegram endpoint
- Fast&Good Builder
- Sesion id's

### Payload (configurable)
- Every Browser on PC data export (With bypassed Appbound V20 Encryption)
- Anti-AV
- Anti-VT
- Anti-VM
- Webcam grab
- Every PC Monitor recording
- Every PC Monitor screenshot
- Every microphone device record
- IP Grab
- PC Name grab

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

Run the builder as administrator.

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
