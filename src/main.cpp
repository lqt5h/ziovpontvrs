#include <windows.h>
#include <shellapi.h>

// ============================================================
// Constants
// ============================================================

#define WM_TRAYICON     (WM_USER + 1)
#define IDM_TRAY_OPEN   40001
#define IDM_TRAY_EXIT   40002
#define IDM_FILE_EXIT   40003

static const WCHAR MUTEX_NAME[]   = L"Local\\ZiovpontvrsAppMutex";
static const WCHAR CLASS_NAME[]   = L"ZiovpontvrsWindowClass";
static const WCHAR WINDOW_TITLE[] = L"Ziovpontvrs";

// ============================================================
// Globals
// ============================================================

static UINT  WM_TASKBARCREATED = 0;
static HWND  g_hwnd            = NULL;
static NOTIFYICONDATAW g_nid   = {};
static BOOL  g_silentStart     = FALSE;

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

// ============================================================
// Window procedure
// ============================================================

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    /* Taskbar recreated (e.g. explorer.exe restart) — re‑add tray icon */
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
            RemoveTrayIcon();
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    case WM_CLOSE:
        /* Hide instead of destroy — keep running in background */
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
                    LPWSTR lpCmdLine, int nCmdShow) {
    /* ---- Single instance check (named mutex) ---- */
    HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    /* ---- Silent‑start flag ---- */
    if (lpCmdLine && (wcsstr(lpCmdLine, L"--silent") || wcsstr(lpCmdLine, L"/silent"))) {
        g_silentStart = TRUE;
    }

    /* ---- Register "TaskbarCreated" message ---- */
    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    /* ---- Register window class ---- */
    WNDCLASSEXW wc   = {};
    wc.cbSize         = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc    = WindowProc;
    wc.hInstance       = hInstance;
    wc.hIcon           = LoadIconW(NULL, IDI_APPLICATION);
    wc.hCursor         = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground   = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName   = CLASS_NAME;
    RegisterClassExW(&wc);

    /* ---- Main window menu: Файл → Выход ---- */
    HMENU hMenuBar  = CreateMenu();
    HMENU hFileMenu = CreateMenu();
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");                 /* Выход */
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu,
                L"\x0424\x0430\x0439\x043B");                        /* Файл  */

    /* ---- Create main window ---- */
    g_hwnd = CreateWindowExW(
        0, CLASS_NAME, WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
        NULL, hMenuBar, hInstance, NULL);

    if (!g_hwnd) {
        CloseHandle(hMutex);
        return 1;
    }

    /* Show window unless started with --silent / /silent */
    if (!g_silentStart) {
        ShowWindow(g_hwnd, nCmdShow);
    }

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
