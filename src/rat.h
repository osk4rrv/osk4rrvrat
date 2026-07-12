#pragma once
#include <string>
#include <functional>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <thread>
#include <atomic>
#include <mutex>

#pragma comment(lib, "winhttp.lib")

enum class TelegramStatus {
    Idle,
    Connecting,
    Connected,
    Failed
};

struct TelegramConfig {
    std::string botToken;
    std::string chatId;
};

struct TelegramState {
    std::atomic<TelegramStatus> status{TelegramStatus::Idle};
    std::string lastError;
    std::string lastResponse;
    std::mutex mtx;
};

class TelegramBot {
public:
    TelegramBot();
    ~TelegramBot();

    void setConfig(const std::string& token, const std::string& chatId);
    void setSessionId(const std::string& id);
    void sendMessageAsync(const std::string& message);
    void sendMessageSync(const std::string& message);
    void sendRawMessageAsync(const std::string& message);
    void sendRawMessageSync(const std::string& message);
    void sendDocumentAsync(const std::string& caption, const std::string& fileName, const std::vector<char>& fileData);
    void sendDocumentSync(const std::string& caption, const std::string& fileName, const std::vector<char>& fileData);
    void verifyConnectionAsync();
    TelegramStatus getStatus() const;
    std::string getLastError();
    std::string getLastResponse();
    bool testConnection();
    bool verifyConnection();
    void reset();

private:
    TelegramConfig config;
    std::string sessionId;
    TelegramState state;
    std::thread worker;

    bool httpRequest(const std::string& path, const std::string& body, std::string& response);
    bool httpRequestMultipart(const std::string& path, const std::string& contentType, const std::string& body, std::string& response);
    bool httpRequestGet(const std::string& path, std::string& response);
    static std::wstring stringToWString(const std::string& s);
    static std::string urlEncode(const std::string& s);
};
