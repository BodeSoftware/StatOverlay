#include <windows.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#include <comdef.h> 
#include <string>
#include <algorithm>
#include <vector>
#include <cstdio>
#include <cwctype>
#include <shellapi.h>

// -----------------------------------------------------------------------
// LIBRARIES - MUST BE LINKED
// -----------------------------------------------------------------------
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

// System tray constants
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001

struct Metrics {
    float cpuTemp = 0.0f;
    float cpuLoad = 0.0f;
    float gpuTemp = 0.0f;
    float gpuLoad = 0.0f;
};

static Metrics g_Metrics;
static HFONT   g_hFont = NULL;
static bool    g_Running = true;

static bool    g_OhmStartedByUs = false;
static HANDLE  g_hOhmProcess = NULL;
static DWORD   g_OhmPid = 0;

static NOTIFYICONDATAW g_nid = {};

// ----------------------------------------------------
// Helper: Case insensitive string search
// ----------------------------------------------------
bool Contains(const std::wstring& haystack, const std::wstring& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](wchar_t ch1, wchar_t ch2) {
            return std::towupper(ch1) == std::towupper(ch2);
        }
    );
    return (it != haystack.end());
}

// ----------------------------------------------------
// Helper: check if OpenHardwareMonitor.exe is running
// ----------------------------------------------------
static bool IsOhmAlreadyRunning(DWORD& outPid)
{
    outPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe))
    {
        do {
            if (_wcsicmp(pe.szExeFile, L"OpenHardwareMonitor.exe") == 0)
            {
                outPid = pe.th32ProcessID;
                CloseHandle(hSnap);
                return true;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return false;
}

// ----------------------------------------------------
// Helper: close OHM if we started it
// ----------------------------------------------------
static void CloseOhmIfWeStartedIt()
{
    if (!g_OhmStartedByUs || !g_hOhmProcess) return;

    HWND hwnd = NULL;
    for (;;)
    {
        hwnd = FindWindowExW(NULL, hwnd, NULL, NULL);
        if (!hwnd) break;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == g_OhmPid)
        {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            break;
        }
    }

    DWORD waitRes = WaitForSingleObject(g_hOhmProcess, 2000);

    if (waitRes == WAIT_TIMEOUT)
    {
        TerminateProcess(g_hOhmProcess, 0);
        WaitForSingleObject(g_hOhmProcess, 1000);
    }

    CloseHandle(g_hOhmProcess);
    g_hOhmProcess = NULL;
}

// ----------------------------------------------------
// Finds the absolute path and executes OHM
// ----------------------------------------------------
static void ExecuteOhmProcess()
{
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) return;

    std::wstring folderPath(exePath);
    size_t lastSlash = folderPath.find_last_of(L'\\');
    if (lastSlash == std::wstring::npos) return;
    folderPath = folderPath.substr(0, lastSlash);

    std::wstring binPath = folderPath + L"\\bin";
    std::wstring ohmPath = binPath + L"\\OpenHardwareMonitor.exe";

    DWORD fileAttr = GetFileAttributesW(binPath.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES || !(fileAttr & FILE_ATTRIBUTE_DIRECTORY))
    {
        binPath = folderPath;
        ohmPath = binPath + L"\\OpenHardwareMonitor.exe";

        if (GetFileAttributesW(ohmPath.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    }

    LPCWSTR lpFile = L"OpenHardwareMonitor.exe";
    LPCWSTR lpParameters = L"/minimized /hide";

    HINSTANCE result = ShellExecuteW(
        NULL,
        L"open",
        ohmPath.c_str(),
        lpParameters,
        NULL,
        SW_HIDE
    );

    if ((int)result > 32)
    {
        g_OhmStartedByUs = true;
        Sleep(1000);

        DWORD newPid = 0;
        if (IsOhmAlreadyRunning(newPid)) {
            g_OhmPid = newPid;
            g_hOhmProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, g_OhmPid);
        }
    }
}

// ----------------------------------------------------
// Helper: ensure OHM is running (and launch hidden if necessary)
// ----------------------------------------------------
static void EnsureOhmRunning()
{
    DWORD existingPid = 0;
    if (IsOhmAlreadyRunning(existingPid))
    {
        g_OhmStartedByUs = false;
        g_OhmPid = existingPid;
        return;
    }

    ExecuteOhmProcess();
}

// ----------------------------------------------------
// WMI: Connect to OHM
// ----------------------------------------------------
static bool InitWmi(IWbemServices** outSvc)
{
    *outSvc = nullptr;
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {}

    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr) || !pLoc) return false;

    IWbemServices* pSvc = nullptr;

    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\OpenHardwareMonitor"), NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    pLoc->Release();

    if (FAILED(hr) || !pSvc) return false;

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    *outSvc = pSvc;
    return true;
}

// ----------------------------------------------------
// WMI: Query Loop
// ----------------------------------------------------
static void UpdateThermalsWmi(IWbemServices* pSvc)
{
    if (!pSvc) return;

    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name, SensorType, Value, Parent FROM Sensor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnum
    );

    if (FAILED(hr) || !pEnum) return;

    float cpuTempMax = 0.0f;
    float gpuTempMax = 0.0f;
    float cpuLoadTotal = 0.0f;
    float gpuLoadTotal = 0.0f;
    int cpuLoadCount = 0;
    int gpuLoadCount = 0;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;

    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK)
    {
        VARIANT vName, vType, vVal, vParent;
        VariantInit(&vName); VariantInit(&vType); VariantInit(&vVal); VariantInit(&vParent);

        pObj->Get(L"Name", 0, &vName, NULL, NULL);
        pObj->Get(L"SensorType", 0, &vType, NULL, NULL);
        pObj->Get(L"Value", 0, &vVal, NULL, NULL);
        pObj->Get(L"Parent", 0, &vParent, NULL, NULL);

        if (vName.vt == VT_BSTR && vType.vt == VT_BSTR && vParent.vt == VT_BSTR &&
            (vVal.vt == VT_R4 || vVal.vt == VT_R8))
        {
            std::wstring name(vName.bstrVal);
            std::wstring type(vType.bstrVal);
            std::wstring parent(vParent.bstrVal);
            float value = (vVal.vt == VT_R4) ? vVal.fltVal : (float)vVal.dblVal;

            bool isCpu = Contains(parent, L"cpu") || Contains(parent, L"processor") || Contains(name, L"cpu") || Contains(name, L"core");
            bool isGpu = Contains(parent, L"gpu") || Contains(parent, L"nvidia") || Contains(parent, L"radeon") || Contains(name, L"gpu");

            if (type == L"Temperature")
            {
                if (value > 0.1f && value < 150.0f) {
                    if (isCpu && value > cpuTempMax) cpuTempMax = value;
                    if (isGpu && value > gpuTempMax) gpuTempMax = value;
                }
            }
            else if (type == L"Load")
            {
                if (isCpu) { cpuLoadTotal += value; cpuLoadCount++; }
                if (isGpu) { gpuLoadTotal += value; gpuLoadCount++; }
            }
        }
        VariantClear(&vName); VariantClear(&vType); VariantClear(&vVal); VariantClear(&vParent);
        pObj->Release();
    }
    pEnum->Release();

    if (cpuTempMax > 0) g_Metrics.cpuTemp = cpuTempMax;
    if (gpuTempMax > 0) g_Metrics.gpuTemp = gpuTempMax;
    if (cpuLoadCount > 0) g_Metrics.cpuLoad = cpuLoadTotal / cpuLoadCount;
    if (gpuLoadCount > 0) g_Metrics.gpuLoad = gpuLoadTotal / gpuLoadCount;
}

// ----------------------------------------------------
// THREAD: Where OHM is launched and data is fetched
// ----------------------------------------------------
static DWORD WINAPI MetricsThreadProc(LPVOID)
{
    EnsureOhmRunning();
    Sleep(10000);

    IWbemServices* pSvc = nullptr;
    while (g_Running)
    {
        if (!pSvc) {
            if (!InitWmi(&pSvc)) {
                Sleep(3000);
                continue;
            }
        }
        UpdateThermalsWmi(pSvc);
        Sleep(1000);
    }
    if (pSvc) pSvc->Release();
    CoUninitialize();
    return 0;
}

// ----------------------------------------------------
// System Tray: Add Icon
// ----------------------------------------------------
static void AddTrayIcon(HWND hwnd)
{
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    lstrcpyW(g_nid.szTip, L"Thermal Overlay");

    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

// ----------------------------------------------------
// System Tray: Remove Icon
// ----------------------------------------------------
static void RemoveTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

// ----------------------------------------------------
// System Tray: Show Context Menu
// ----------------------------------------------------
static void ShowTrayMenu(HWND hwnd)
{
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

// ----------------------------------------------------
// WINDOWS GUI
// ----------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        AddTrayIcon(hwnd);
        return 0;

    case WM_DESTROY:
        g_Running = false;
        if (g_hFont) DeleteObject(g_hFont);
        RemoveTrayIcon();
        CloseOhmIfWeStartedIt();
        PostQuitMessage(0);
        return 0;

    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP)
        {
            ShowTrayMenu(hwnd);
        }
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_TRAY_EXIT)
        {
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_TIMER:
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        HBRUSH hBlack = (HBRUSH)GetStockObject(BLACK_BRUSH);
        FillRect(hdc, &ps.rcPaint, hBlack);

        SelectObject(hdc, g_hFont);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));

        wchar_t buf[256];
        int x = 10, y = 10, line = 25;

        swprintf_s(buf, 256, L"CPU: %.0f C  |  %.0f%%", g_Metrics.cpuTemp, g_Metrics.cpuLoad);
        TextOutW(hdc, x, y, buf, lstrlenW(buf)); y += line;

        swprintf_s(buf, 256, L"GPU: %.0f C  |  %.0f%%", g_Metrics.gpuTemp, g_Metrics.gpuLoad);
        TextOutW(hdc, x, y, buf, lstrlenW(buf));

        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(_In_ HINSTANCE hInst, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int nCmdShow)
{
    LOGFONTW lf = {};
    lf.lfHeight = -20;
    lf.lfWeight = FW_BOLD;
    lf.lfQuality = CLEARTYPE_QUALITY;
    lstrcpyW(lf.lfFaceName, L"Segoe UI");
    g_hFont = CreateFontIndirectW(&lf);

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"ThermalOverlayClass";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassW(&wc);

    int width = 240, height = 80;
    int screenW = GetSystemMetrics(SM_CXSCREEN);

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
        wc.lpszClassName, L"", WS_POPUP,
        screenW - width - 20, 20, width, height,
        NULL, NULL, hInst, NULL
    );

    if (!hwnd) return 0;

    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);

    ShowWindow(hwnd, nCmdShow);

    HANDLE hThread = CreateThread(NULL, 0, MetricsThreadProc, NULL, 0, NULL);
    SetTimer(hwnd, 1, 1000, NULL);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (hThread) { WaitForSingleObject(hThread, 1000); CloseHandle(hThread); }
    return (int)msg.wParam;
}