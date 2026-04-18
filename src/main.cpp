#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <rpc.h>
#include <stdlib.h>

extern "C" {
#include "rpc_iface.h"
}
#include "rpc_common.h"

// ============================================================
// Constants
// ============================================================

#define WM_TRAYICON     (WM_USER + 1)
#define IDM_TRAY_OPEN   40001
#define IDM_TRAY_EXIT   40002
#define IDM_FILE_EXIT   40003

static const WCHAR MUTEX_NAME[]      = L"Local\\ZiovpontvrsAppMutex";
static const WCHAR CLASS_NAME[]      = L"ZiovpontvrsWindowClass";
static const WCHAR WINDOW_TITLE[]    = L"Ziovpontvrs";
static const WCHAR SERVICE_NAME[]    = L"ZiovpontvrsSvc";
static const WCHAR SVC_EXE_NAME[]    = L"ziovpontvrs_svc.exe";

// ============================================================
// Globals
// ============================================================

static UINT  WM_TASKBARCREATED = 0;
static HWND  g_hwnd            = NULL;
static NOTIFYICONDATAW g_nid   = {};

// ============================================================
// RPC — MIDL allocator hooks + shutdown client
// ============================================================

extern "C" void * __RPC_USER MIDL_user_allocate(size_t size) {
    return malloc(size);
}

extern "C" void __RPC_USER MIDL_user_free(void *p) {
    free(p);
}

static void StopServiceViaRpc(void) {
    RPC_WSTR stringBinding = NULL;
    if (RpcStringBindingComposeW(NULL,
                                 ZIOVPONTVRS_RPC_PROTSEQ,
                                 NULL,
                                 ZIOVPONTVRS_RPC_ENDPOINT,
                                 NULL,
                                 &stringBinding) != RPC_S_OK) {
        return;
    }

    handle_t hBinding = NULL;
    RPC_STATUS rs = RpcBindingFromStringBindingW(stringBinding, &hBinding);
    RpcStringFreeW(&stringBinding);
    if (rs != RPC_S_OK) return;

    ZiovpontvrsRpc_IfHandle = hBinding;
    RpcShutdown();
    RpcBindingFree(&hBinding);
    ZiovpontvrsRpc_IfHandle = NULL;
}

// ============================================================
// Service state helpers
// ============================================================

/* Returns the current state (SERVICE_RUNNING / SERVICE_STOPPED / ...) or 0
 * if the service cannot be queried. */
static DWORD QueryServiceState(void) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return 0;
    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
    DWORD state = 0;
    if (hSvc) {
        SERVICE_STATUS st = {};
        if (QueryServiceStatus(hSvc, &st)) state = st.dwCurrentState;
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    return state;
}

/* Starts the service and polls until it reports SERVICE_RUNNING (or we give
 * up after ~30 seconds). */
static BOOL StartServiceAndWaitRunning(void) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;
    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME,
                                  SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hSvc) { CloseServiceHandle(hSCM); return FALSE; }

    BOOL started = StartServiceW(hSvc, 0, NULL);
    if (!started && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL running = FALSE;
    for (int i = 0; i < 60; i++) {
        SERVICE_STATUS st = {};
        if (QueryServiceStatus(hSvc, &st) &&
            st.dwCurrentState == SERVICE_RUNNING) {
            running = TRUE;
            break;
        }
        Sleep(500);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return running;
}

// ============================================================
// Parent-process check
// ============================================================

static DWORD GetParentProcessId(void) {
    DWORD myPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    DWORD ppid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return ppid;
}

static BOOL ParentIsService(void) {
    DWORD ppid = GetParentProcessId();
    if (!ppid) return FALSE;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!hProc) return FALSE;

    WCHAR path[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(hProc, 0, path, &sz);
    CloseHandle(hProc);
    if (!ok) return FALSE;

    const WCHAR *name = wcsrchr(path, L'\\');
    name = name ? name + 1 : path;
    return _wcsicmp(name, SVC_EXE_NAME) == 0;
}

// ============================================================
// Tray icon helpers
// ============================================================

static void AddTrayIcon(HWND hwnd) {
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize           = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd             = hwnd;
    g_nid.uID              = 1;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon            = LoadIconW(NULL, IDI_APPLICATION);
    wcsncpy(g_nid.szTip, WINDOW_TITLE, sizeof(g_nid.szTip) / sizeof(WCHAR) - 1);
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void RemoveTrayIcon(void) {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

// ============================================================
// Window helpers
// ============================================================

static void ShowAppWindow(HWND hwnd) {
    ShowWindow(hwnd, SW_SHOW);
    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
}

static void ShowTrayContextMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_OPEN, L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C");   /* Открыть */
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"\x0412\x044B\x0445\x043E\x0434");               /* Выход   */

    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

/* Exit menu item: tell the service to shut down through RPC. The service
 * will TerminateProcess this GUI as part of its teardown; we also tear
 * down locally in case the RPC round-trip returns first. */
static void RequestServiceShutdown(HWND hwnd) {
    StopServiceViaRpc();
    RemoveTrayIcon();
    DestroyWindow(hwnd);
}

// ============================================================
// Window procedure
// ============================================================

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    /* Taskbar recreated (e.g. explorer.exe restart) — re-add tray icon */
    if (msg == WM_TASKBARCREATED && WM_TASKBARCREATED != 0) {
        AddTrayIcon(hwnd);
        return 0;
    }

    switch (msg) {
    case WM_CREATE:
        AddTrayIcon(hwnd);
        return 0;

    case WM_TRAYICON:
        switch (lParam) {
        case WM_LBUTTONUP:
            ShowAppWindow(hwnd);
            break;
        case WM_RBUTTONUP:
            ShowTrayContextMenu(hwnd);
            break;
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_TRAY_OPEN:
            ShowAppWindow(hwnd);
            break;
        case IDM_TRAY_EXIT:
        case IDM_FILE_EXIT:
            RequestServiceShutdown(hwnd);
            break;
        }
        return 0;

    case WM_CLOSE:
        /* Hide instead of destroy — keep running in background. */
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ============================================================
// Entry point
// ============================================================

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/,
                    LPWSTR /*lpCmdLine*/, int /*nCmdShow*/) {
    /* ---- Requirement 1: if the service is stopped, start it, wait until
     *      it reports Running, and terminate this instance. ---- */
    if (QueryServiceState() == SERVICE_STOPPED) {
        StartServiceAndWaitRunning();
        return 0;
    }

    /* ---- Requirement 2: only continue when launched by the service. ---- */
    if (!ParentIsService()) {
        return 0;
    }

    /* ---- Single-instance guard (per-session) ---- */
    HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    /* ---- Register "TaskbarCreated" broadcast message ---- */
    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    /* ---- Register window class ---- */
    WNDCLASSEXW wc = {};
    wc.cbSize         = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc    = WindowProc;
    wc.hInstance      = hInstance;
    wc.hIcon          = LoadIconW(NULL, IDI_APPLICATION);
    wc.hCursor        = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground  = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName  = CLASS_NAME;
    RegisterClassExW(&wc);

    /* ---- Main window menu: Файл → Выход ---- */
    HMENU hMenuBar  = CreateMenu();
    HMENU hFileMenu = CreateMenu();
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");                 /* Выход */
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu,
                L"\x0424\x0430\x0439\x043B");                        /* Файл  */

    /* ---- Create main window (hidden per spec) ---- */
    g_hwnd = CreateWindowExW(
        0, CLASS_NAME, WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
        NULL, hMenuBar, hInstance, NULL);

    if (!g_hwnd) {
        CloseHandle(hMutex);
        return 1;
    }

    /* Spec: the main window must remain hidden at startup. */
    ShowWindow(g_hwnd, SW_HIDE);

    /* ---- Message loop ---- */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return (int)msg.wParam;
}
