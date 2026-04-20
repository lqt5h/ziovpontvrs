#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <rpc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

extern "C" {
#include "rpc_iface.h"
}
#include "rpc_common.h"

/* Result codes — must stay in sync with auth::ResultCode in auth_state.h.
 * The GUI doesn't link auth_state.cpp (those live inside the service
 * process); the codes are duplicated here as plain constants. */
enum {
    AUTH_OK                   = 0,
    AUTH_ERR_UNAUTHENTICATED  = 1,
    AUTH_ERR_NETWORK          = 2,
    AUTH_ERR_BAD_CREDENTIALS  = 3,
    AUTH_ERR_LICENSE_MISSING  = 4,
    AUTH_ERR_ACTIVATION       = 5,
    AUTH_ERR_INTERNAL         = 6,
};

// ============================================================
// Window / control IDs
// ============================================================

#define WM_TRAYICON       (WM_USER + 1)

#define IDM_FILE_EXIT     40001
#define IDM_ACCT_LOGOUT   40002
#define IDM_TRAY_OPEN     40003
#define IDM_TRAY_EXIT     40004

#define IDC_LOGIN_USER    50001
#define IDC_LOGIN_PASS    50002
#define IDC_LOGIN_BTN     50003
#define IDC_ACT_CODE      50004
#define IDC_ACT_BTN       50005
#define IDC_DASH_SCAN     50007

#define IDT_LICENSE_POLL  1

static const WCHAR MUTEX_NAME[]   = L"Local\\ZiovpontvrsAppMutex";
static const WCHAR CLASS_NAME[]   = L"ZiovpontvrsWindowClass";
static const WCHAR WINDOW_TITLE[] = L"Ziovpontvrs";
static const WCHAR SERVICE_NAME[] = L"ZiovpontvrsSvc";
static const WCHAR SVC_EXE_NAME[] = L"ziovpontvrs_svc.exe";

// ============================================================
// Globals
// ============================================================

static UINT   WM_TASKBARCREATED = 0;
static HWND   g_hwnd            = NULL;
static NOTIFYICONDATAW g_nid    = {};

/* Page state */
enum Page { PAGE_LOGIN = 0, PAGE_ACTIVATION = 1, PAGE_DASHBOARD = 2 };
static Page g_page = PAGE_LOGIN;

/* Child controls, grouped by page */
static HWND g_loginTitle, g_loginUserLbl, g_loginUserEdit,
            g_loginPassLbl, g_loginPassEdit, g_loginBtn, g_loginError;

static HWND g_actTitle, g_actUserLbl, g_actCodeLbl, g_actCodeEdit,
            g_actBtn, g_actError;

static HWND g_dashTitle, g_dashUserLbl, g_dashExpiryLbl,
            g_dashScanBtn, g_dashScanStatus;

static WCHAR g_currentUser[256] = L"";

// ============================================================
// RPC — MIDL allocator hooks + persistent binding
// ============================================================

extern "C" void *__RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
extern "C" void  __RPC_USER MIDL_user_free   (void *p)       { free(p); }

static BOOL OpenRpcBinding(void) {
    RPC_WSTR sb = NULL;
    if (RpcStringBindingComposeW(NULL,
                                 ZIOVPONTVRS_RPC_PROTSEQ,
                                 NULL,
                                 ZIOVPONTVRS_RPC_ENDPOINT,
                                 NULL, &sb) != RPC_S_OK) return FALSE;

    handle_t hBinding = NULL;
    RPC_STATUS rs = RpcBindingFromStringBindingW(sb, &hBinding);
    RpcStringFreeW(&sb);
    if (rs != RPC_S_OK) return FALSE;

    ZiovpontvrsRpc_IfHandle = hBinding;
    return TRUE;
}

static void CloseRpcBinding(void) {
    if (ZiovpontvrsRpc_IfHandle) {
        handle_t h = ZiovpontvrsRpc_IfHandle;
        ZiovpontvrsRpc_IfHandle = NULL;
        RpcBindingFree(&h);
    }
}

// ============================================================
// Service state helpers (task-2 — unchanged)
// ============================================================

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

static BOOL StartServiceAndWaitRunning(void) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;
    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME,
                                  SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hSvc) { CloseServiceHandle(hSCM); return FALSE; }

    BOOL started = StartServiceW(hSvc, 0, NULL);
    if (!started && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        CloseServiceHandle(hSvc); CloseServiceHandle(hSCM); return FALSE;
    }

    BOOL running = FALSE;
    for (int i = 0; i < 60; i++) {
        SERVICE_STATUS st = {};
        if (QueryServiceStatus(hSvc, &st) &&
            st.dwCurrentState == SERVICE_RUNNING) { running = TRUE; break; }
        Sleep(500);
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return running;
}

static DWORD GetParentProcessId(void) {
    DWORD myPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    DWORD ppid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) { ppid = pe.th32ParentProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return ppid;
}

static BOOL IsElevated(void) {
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te = {};
        DWORD sz = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &sz))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated;
}

static void RelaunchElevated(void) {
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    ShellExecuteW(NULL, L"runas", path, L"--elevate", NULL, SW_HIDE);
}

static BOOL InstallAndStartService(void) {
    WCHAR svcPath[MAX_PATH];
    GetModuleFileNameW(NULL, svcPath, MAX_PATH);
    WCHAR *slash = wcsrchr(svcPath, L'\\');
    if (slash)
        wcscpy_s(slash + 1,
                 MAX_PATH - (DWORD)(slash + 1 - svcPath),
                 SVC_EXE_NAME);

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL,
                                    SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCM) {
        MessageBoxW(NULL, L"OpenSCManager failed", WINDOW_TITLE, MB_ICONERROR);
        return FALSE;
    }

    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (hSvc) {
        SERVICE_STATUS st = {};
        QueryServiceStatus(hSvc, &st);
        if (st.dwCurrentState != SERVICE_STOPPED) {
            ControlService(hSvc, SERVICE_CONTROL_STOP, &st);
            for (int i = 0; i < 20; i++) {
                QueryServiceStatus(hSvc, &st);
                if (st.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(500);
            }
        }
        ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                             SERVICE_NO_CHANGE, svcPath,
                             NULL, NULL, NULL, NULL, NULL, NULL);
    } else {
        hSvc = CreateServiceW(
            hSCM, SERVICE_NAME, L"Ziovpontvrs Service",
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
            svcPath, NULL, NULL, NULL, NULL, NULL);
        if (hSvc) {
            SERVICE_DESCRIPTIONW desc = {};
            desc.lpDescription =
                const_cast<LPWSTR>(L"Ziovpontvrs background service");
            ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);
        }
    }

    if (!hSvc) {
        DWORD err = GetLastError();
        WCHAR buf[128];
        swprintf(buf, 128, L"Service create/open failed (error %lu)", err);
        MessageBoxW(NULL, buf, WINDOW_TITLE, MB_ICONERROR);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    if (!StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            WCHAR buf[128];
            swprintf(buf, 128, L"StartService failed (error %lu)", err);
            MessageBoxW(NULL, buf, WINDOW_TITLE, MB_ICONERROR);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return FALSE;
        }
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
    if (!running)
        MessageBoxW(NULL, L"Service did not reach RUNNING state",
                    WINDOW_TITLE, MB_ICONERROR);
    return running;
}

static BOOL ParentIsService(void) {
    DWORD ppid = GetParentProcessId();
    if (!ppid) return FALSE;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!hProc) return FALSE;
    WCHAR path[MAX_PATH] = {}; DWORD sz = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(hProc, 0, path, &sz);
    CloseHandle(hProc);
    if (!ok) return FALSE;
    const WCHAR *name = wcsrchr(path, L'\\');
    name = name ? name + 1 : path;
    return _wcsicmp(name, SVC_EXE_NAME) == 0;
}

// ============================================================
// Tray icon helpers (task-2 — unchanged)
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

static void RemoveTrayIcon(void) { Shell_NotifyIconW(NIM_DELETE, &g_nid); }

static void ShowAppWindow(HWND hwnd) {
    ShowWindow(hwnd, SW_SHOW);
    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
}

static void ShowTrayContextMenu(HWND hwnd) {
    POINT pt; GetCursorPos(&pt);
    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_OPEN,
                L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C");  /* Открыть */
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");              /* Выход   */
    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

static void RequestServiceShutdown(HWND hwnd) {
    /* Tell the service to shut down via RPC. */
    RpcShutdown();
    RemoveTrayIcon();
    DestroyWindow(hwnd);
}

// ============================================================
// Page helpers
// ============================================================

static void SetTextW(HWND h, const wchar_t *s) {
    SetWindowTextW(h, s ? s : L"");
}

static void HideAllPages(void) {
    HWND login[]      = { g_loginTitle, g_loginUserLbl, g_loginUserEdit,
                          g_loginPassLbl, g_loginPassEdit, g_loginBtn, g_loginError };
    HWND activation[] = { g_actTitle, g_actUserLbl, g_actCodeLbl,
                          g_actCodeEdit, g_actBtn, g_actError };
    HWND dashboard[]  = { g_dashTitle, g_dashUserLbl, g_dashExpiryLbl,
                          g_dashScanBtn, g_dashScanStatus };

    for (HWND h : login)      ShowWindow(h, SW_HIDE);
    for (HWND h : activation) ShowWindow(h, SW_HIDE);
    for (HWND h : dashboard)  ShowWindow(h, SW_HIDE);
}

static void ShowPage(Page p) {
    g_page = p;
    HideAllPages();

    HWND *page = NULL;
    HWND login[]      = { g_loginTitle, g_loginUserLbl, g_loginUserEdit,
                          g_loginPassLbl, g_loginPassEdit, g_loginBtn, g_loginError };
    HWND activation[] = { g_actTitle, g_actUserLbl, g_actCodeLbl,
                          g_actCodeEdit, g_actBtn, g_actError };
    HWND dashboard[]  = { g_dashTitle, g_dashUserLbl, g_dashExpiryLbl,
                          g_dashScanBtn, g_dashScanStatus };

    int n = 0;
    switch (p) {
        case PAGE_LOGIN:      page = login;      n = sizeof(login)      / sizeof(HWND); break;
        case PAGE_ACTIVATION: page = activation; n = sizeof(activation) / sizeof(HWND); break;
        case PAGE_DASHBOARD:  page = dashboard;  n = sizeof(dashboard)  / sizeof(HWND); break;
    }
    for (int i = 0; i < n; i++) ShowWindow(page[i], SW_SHOW);
}

static void FormatFileTime(LONGLONG ft, wchar_t *out, size_t n) {
    FILETIME  file = { (DWORD)ft, (DWORD)(ft >> 32) };
    FILETIME  local;
    SYSTEMTIME st;
    FileTimeToLocalFileTime(&file, &local);
    if (!FileTimeToSystemTime(&local, &st)) {
        wcsncpy(out, L"?", n); out[n - 1] = 0; return;
    }
    swprintf(out, n, L"%02u.%02u.%04u %02u:%02u",
             st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
}

// ============================================================
// State-driven UI refresh — called at startup, after RPC actions,
// and on the license poll timer
// ============================================================

static void RefreshUi(HWND hwnd) {
    long  isAuth = 0;
    WCHAR *rpcName = NULL;
    g_currentUser[0] = L'\0';
    if (RpcGetCurrentUser(&isAuth, &rpcName) != AUTH_OK) {
        isAuth = 0;
    }
    if (rpcName) {
        wcsncpy(g_currentUser, rpcName, 255);
        g_currentUser[255] = L'\0';
        MIDL_user_free(rpcName);
    }

    if (!isAuth) {
        ShowPage(PAGE_LOGIN);
        ShowAppWindow(hwnd);
        return;
    }

    /* Authenticated — surface the username and check license. */
    {
        WCHAR buf[320];
        swprintf(buf, 320, L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: %s",
                 g_currentUser);                              /* Пользователь: %s */
        SetTextW(g_dashUserLbl, buf);
        SetTextW(g_actUserLbl,  buf);
    }

    long     hasLicense = 0;
    LONGLONG expFt      = 0;
    RpcGetLicenseStatus(&hasLicense, &expFt);

    if (!hasLicense) {
        ShowPage(PAGE_ACTIVATION);
        ShowAppWindow(hwnd);
        return;
    }

    /* Licensed — fill the dashboard and leave window state as-is (tray). */
    WCHAR when[64];
    FormatFileTime(expFt, when, 64);
    WCHAR expLine[160];
    swprintf(expLine, 160,
             L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F \x0434\x0435\x0439\x0441\x0442\x0432\x0438\x0442\x0435\x043B\x044C\x043D\x0430 \x0434\x043E: %s",  /* Лицензия действительна до: %s */
             when);
    SetTextW(g_dashExpiryLbl, expLine);
    ShowPage(PAGE_DASHBOARD);
}

// ============================================================
// Action handlers
// ============================================================

static void OnLoginClicked(HWND hwnd) {
    WCHAR user[128] = L"";
    WCHAR pass[128] = L"";
    GetWindowTextW(g_loginUserEdit, user, 128);
    GetWindowTextW(g_loginPassEdit, pass, 128);

    if (user[0] == L'\0' || pass[0] == L'\0') {
        SetTextW(g_loginError,
                 L"\x0412\x0432\x0435\x0434\x0438\x0442\x0435 \x043B\x043E\x0433\x0438\x043D \x0438 \x043F\x0430\x0440\x043E\x043B\x044C");  /* Введите логин и пароль */
        return;
    }

    long rc = RpcLogin(user, pass);

    /* Always wipe the password field after a login attempt. */
    SetTextW(g_loginPassEdit, L"");

    if (rc != AUTH_OK) {
        SetTextW(g_loginError,
                 L"\x041D\x0435\x0432\x0435\x0440\x043D\x044B\x0439 \x043B\x043E\x0433\x0438\x043D \x0438\x043B\x0438 \x043F\x0430\x0440\x043E\x043B\x044C");  /* Неверный логин или пароль */
        ShowPage(PAGE_LOGIN);
        return;
    }

    SetTextW(g_loginError, L"");
    RefreshUi(hwnd);
}

static void OnActivateClicked(HWND hwnd) {
    WCHAR code[128] = L"";
    GetWindowTextW(g_actCodeEdit, code, 128);
    if (code[0] == L'\0') {
        SetTextW(g_actError,
                 L"\x0412\x0432\x0435\x0434\x0438\x0442\x0435 \x043A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438");  /* Введите код активации */
        return;
    }

    long rc = RpcActivateProduct(code);
    if (rc != AUTH_OK) {
        SetTextW(g_actError,
                 L"\x041A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438 \x043D\x0435\x0432\x0435\x0440\x0435\x043D");  /* Код активации неверен */
        ShowPage(PAGE_ACTIVATION);
        return;
    }

    SetTextW(g_actError, L"");
    SetTextW(g_actCodeEdit, L"");
    RefreshUi(hwnd);
}

static void OnAccountLogout(HWND hwnd) {
    RpcLogout();
    RefreshUi(hwnd);
}

static void OnScanClicked(HWND /*hwnd*/) {
    long rc = RpcAntivirusScan();
    if (rc == AUTH_OK) {
        SetTextW(g_dashScanStatus,
                 L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435 \x0437\x0430\x043F\x0443\x0449\x0435\x043D\x043E");  /* Сканирование запущено */
    } else if (rc == AUTH_ERR_LICENSE_MISSING) {
        SetTextW(g_dashScanStatus,
                 L"\x041D\x0435\x0442 \x043B\x0438\x0446\x0435\x043D\x0437\x0438\x0438");  /* Нет лицензии */
    } else {
        SetTextW(g_dashScanStatus,
                 L"\x041E\x0448\x0438\x0431\x043A\x0430");  /* Ошибка */
    }
}

// ============================================================
// Child-control creation
// ============================================================

static HWND MkLabel (HWND parent, int id, int x, int y, int w, int h, const wchar_t *s) {
    return CreateWindowExW(0, L"STATIC", s, WS_CHILD,
                           x, y, w, h, parent, (HMENU)(intptr_t)id, NULL, NULL);
}
static HWND MkEdit  (HWND parent, int id, int x, int y, int w, int h, DWORD extra) {
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                           WS_CHILD | WS_TABSTOP | extra,
                           x, y, w, h, parent, (HMENU)(intptr_t)id, NULL, NULL);
}
static HWND MkButton(HWND parent, int id, int x, int y, int w, int h, const wchar_t *s) {
    return CreateWindowExW(0, L"BUTTON", s,
                           WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                           x, y, w, h, parent, (HMENU)(intptr_t)id, NULL, NULL);
}

static void CreatePages(HWND hwnd) {
    /* --- Login page (y: 10..220) --- */
    g_loginTitle    = MkLabel (hwnd, 0, 20,  10, 400, 24,
                               L"\x0410\x0432\x0442\x043E\x0440\x0438\x0437\x0430\x0446\x0438\x044F");  /* Авторизация */
    g_loginUserLbl  = MkLabel (hwnd, 0, 20,  50, 100, 20,
                               L"\x041B\x043E\x0433\x0438\x043D:");  /* Логин: */
    g_loginUserEdit = MkEdit  (hwnd, IDC_LOGIN_USER,  130,  48, 260, 22, 0);
    g_loginPassLbl  = MkLabel (hwnd, 0, 20,  80, 100, 20,
                               L"\x041F\x0430\x0440\x043E\x043B\x044C:");  /* Пароль: */
    g_loginPassEdit = MkEdit  (hwnd, IDC_LOGIN_PASS,  130,  78, 260, 22, ES_PASSWORD);
    g_loginBtn      = MkButton(hwnd, IDC_LOGIN_BTN,   130, 110, 120, 28,
                               L"\x0412\x043E\x0439\x0442\x0438");  /* Войти */
    g_loginError    = MkLabel (hwnd, 0, 20, 150, 400, 40, L"");

    /* --- Activation page (same coords, different controls) --- */
    g_actTitle    = MkLabel (hwnd, 0, 20,  10, 400, 24,
                             L"\x0410\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x044F \x043F\x0440\x043E\x0434\x0443\x043A\x0442\x0430");  /* Активация продукта */
    g_actUserLbl  = MkLabel (hwnd, 0, 20,  50, 400, 20, L"");
    g_actCodeLbl  = MkLabel (hwnd, 0, 20,  80, 150, 20,
                             L"\x041A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438:");  /* Код активации: */
    g_actCodeEdit = MkEdit  (hwnd, IDC_ACT_CODE, 180,  78, 240, 22, 0);
    g_actBtn      = MkButton(hwnd, IDC_ACT_BTN,  180, 110, 160, 28,
                             L"\x0410\x043A\x0442\x0438\x0432\x0438\x0440\x043E\x0432\x0430\x0442\x044C");  /* Активировать */
    g_actError    = MkLabel (hwnd, 0, 20, 150, 400, 40, L"");

    /* --- Dashboard page --- */
    g_dashTitle      = MkLabel (hwnd, 0, 20,  10, 400, 24,
                                L"\x0417\x0430\x0449\x0438\x0442\x0430 \x0430\x043A\x0442\x0438\x0432\x043D\x0430");  /* Защита активна */
    g_dashUserLbl    = MkLabel (hwnd, 0, 20,  50, 400, 20, L"");
    g_dashExpiryLbl  = MkLabel (hwnd, 0, 20,  80, 400, 20, L"");
    g_dashScanBtn    = MkButton(hwnd, IDC_DASH_SCAN, 20, 120, 200, 32,
                                L"\x0417\x0430\x043F\x0443\x0441\x0442\x0438\x0442\x044C \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435");  /* Запустить сканирование */
    g_dashScanStatus = MkLabel (hwnd, 0, 20, 160, 400, 40, L"");
}

// ============================================================
// Window procedure
// ============================================================

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_TASKBARCREATED && WM_TASKBARCREATED != 0) { AddTrayIcon(hwnd); return 0; }

    switch (msg) {
    case WM_CREATE:
        AddTrayIcon(hwnd);
        CreatePages(hwnd);
        /* Poll the license state every 15s so the UI keeps up with the
         * refresh thread in the service. */
        SetTimer(hwnd, IDT_LICENSE_POLL, 15000, NULL);
        return 0;

    case WM_TIMER:
        if (wParam == IDT_LICENSE_POLL) {
            /* Silent refresh — do NOT auto-raise the window if we're
             * already on the dashboard and stayed licensed. */
            long   isAuth  = 0;
            WCHAR *rpcName = NULL;
            RpcGetCurrentUser(&isAuth, &rpcName);
            if (rpcName) MIDL_user_free(rpcName);
            long     hasLicense = 0;
            LONGLONG expFt      = 0;
            RpcGetLicenseStatus(&hasLicense, &expFt);

            if (!isAuth) {
                if (g_page != PAGE_LOGIN)      { ShowPage(PAGE_LOGIN);      ShowAppWindow(hwnd); }
            } else if (!hasLicense) {
                if (g_page != PAGE_ACTIVATION) { ShowPage(PAGE_ACTIVATION); ShowAppWindow(hwnd); }
            } else {
                /* stay licensed — only update the expiry label */
                WCHAR when[64];
                FormatFileTime(expFt, when, 64);
                WCHAR expLine[160];
                swprintf(expLine, 160,
                         L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F \x0434\x0435\x0439\x0441\x0442\x0432\x0438\x0442\x0435\x043B\x044C\x043D\x0430 \x0434\x043E: %s",
                         when);
                SetTextW(g_dashExpiryLbl, expLine);
                if (g_page != PAGE_DASHBOARD) ShowPage(PAGE_DASHBOARD);
            }
        }
        return 0;

    case WM_TRAYICON:
        switch (lParam) {
        case WM_LBUTTONUP: ShowAppWindow(hwnd); break;
        case WM_RBUTTONUP: ShowTrayContextMenu(hwnd); break;
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_TRAY_OPEN:   ShowAppWindow(hwnd);           break;
        case IDM_TRAY_EXIT:
        case IDM_FILE_EXIT:   RequestServiceShutdown(hwnd);  break;
        case IDM_ACCT_LOGOUT: OnAccountLogout(hwnd);         break;
        case IDC_LOGIN_BTN:   OnLoginClicked(hwnd);          break;
        case IDC_ACT_BTN:     OnActivateClicked(hwnd);       break;
        case IDC_DASH_SCAN:   OnScanClicked(hwnd);           break;
        }
        return 0;

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_LICENSE_POLL);
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
    DWORD svcState = QueryServiceState();

    if (svcState != SERVICE_RUNNING) {
        if (!IsElevated()) {
            RelaunchElevated();
            return 0;
        }
        if (!InstallAndStartService())
            return 1;
    }

    HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIconW(NULL, IDI_APPLICATION);
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    /* Menus — Файл / Аккаунт */
    HMENU hMenuBar  = CreateMenu();
    HMENU hFileMenu = CreateMenu();
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");                             /* Выход   */
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu,
                L"\x0424\x0430\x0439\x043B");                                   /* Файл    */
    HMENU hAccMenu = CreateMenu();
    AppendMenuW(hAccMenu, MF_STRING, IDM_ACCT_LOGOUT,
                L"\x0412\x044B\x0439\x0442\x0438 \x0438\x0437 \x0430\x043A\x043A\x0430\x0443\x043D\x0442\x0430");  /* Выйти из аккаунта */
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hAccMenu,
                L"\x0410\x043A\x043A\x0430\x0443\x043D\x0442");                 /* Аккаунт */

    g_hwnd = CreateWindowExW(
        0, CLASS_NAME, WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 520, 360,
        NULL, hMenuBar, hInstance, NULL);

    if (!g_hwnd) { CloseHandle(hMutex); return 1; }

    /* Task-1: main window hidden on start. */
    ShowWindow(g_hwnd, SW_HIDE);

    /* RPC binding — persists for the process lifetime. */
    if (!OpenRpcBinding()) {
        CloseHandle(hMutex);
        return 1;
    }

    /* Initial UI pass — will raise the window if login / activation is
     * required, otherwise leave it hidden in the tray. */
    RefreshUi(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseRpcBinding();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return (int)msg.wParam;
}
