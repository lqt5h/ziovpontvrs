#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <stdio.h>

// ============================================================
// Constants
// ============================================================

#define SERVICE_NAME L"ZiovpontvrsSvc"

// ============================================================
// Globals
// ============================================================

static SERVICE_STATUS        g_svcStatus       = {};
static SERVICE_STATUS_HANDLE g_svcStatusHandle = NULL;
static HANDLE                g_svcStopEvent    = NULL;

// ============================================================
// Helper — path to the GUI executable (same directory)
// ============================================================

static BOOL GetGuiExePath(WCHAR *buf, DWORD bufLen) {
    DWORD n = GetModuleFileNameW(NULL, buf, bufLen);
    if (n == 0 || n >= bufLen) return FALSE;
    WCHAR *slash = wcsrchr(buf, L'\\');
    if (!slash) return FALSE;
    wcscpy_s(slash + 1, bufLen - (DWORD)(slash + 1 - buf), L"ziovpontvrs.exe");
    return TRUE;
}

// ============================================================
// Launch the GUI app inside a given user session (hidden)
// ============================================================

static void LaunchGuiInSession(DWORD sessionId) {
    WCHAR guiPath[MAX_PATH];
    if (!GetGuiExePath(guiPath, MAX_PATH)) return;

    WCHAR cmdLine[MAX_PATH + 32];
    swprintf(cmdLine, sizeof(cmdLine) / sizeof(WCHAR),
             L"\"%s\" --silent", guiPath);

    HANDLE hToken = NULL;
    if (!WTSQueryUserToken(sessionId, &hToken)) return;

    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityIdentification, TokenPrimary, &hDupToken)) {
        CloseHandle(hToken);
        return;
    }
    CloseHandle(hToken);

    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hDupToken, FALSE);

    STARTUPINFOW si = {};
    si.cb        = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION pi = {};
    CreateProcessAsUserW(hDupToken, NULL, cmdLine, NULL, NULL, FALSE,
                         CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                         pEnv, NULL, &si, &pi);

    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    if (pEnv)        DestroyEnvironmentBlock(pEnv);
    CloseHandle(hDupToken);
}

// ============================================================
// Launch GUI in every currently active desktop session
// ============================================================

static void LaunchGuiInAllSessions(void) {
    PWTS_SESSION_INFOW pSessions = NULL;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                               &pSessions, &count))
        return;

    for (DWORD i = 0; i < count; i++) {
        if (pSessions[i].State == WTSActive) {
            LaunchGuiInSession(pSessions[i].SessionId);
        }
    }
    WTSFreeMemory(pSessions);
}

// ============================================================
// Report service status to the SCM
// ============================================================

static void SvcReportStatus(DWORD state, DWORD exitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;

    g_svcStatus.dwCurrentState  = state;
    g_svcStatus.dwWin32ExitCode = exitCode;
    g_svcStatus.dwWaitHint      = waitHint;

    if (state == SERVICE_START_PENDING)
        g_svcStatus.dwControlsAccepted = 0;
    else
        g_svcStatus.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;

    g_svcStatus.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;

    SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
}

// ============================================================
// Service control handler (stop, session‑change, etc.)
// ============================================================

static DWORD WINAPI SvcCtrlHandlerEx(DWORD dwControl, DWORD dwEventType,
                                     LPVOID lpEventData, LPVOID /*lpContext*/) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
        SvcReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(g_svcStopEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE:
        if (dwEventType == WTS_SESSION_LOGON) {
            auto *pNotif = reinterpret_cast<WTSSESSION_NOTIFICATION *>(lpEventData);
            if (pNotif) {
                Sleep(3000);                        /* let the session initialise */
                LaunchGuiInSession(pNotif->dwSessionId);
            }
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

// ============================================================
// ServiceMain
// ============================================================

static void WINAPI SvcMain(DWORD /*argc*/, LPWSTR * /*argv*/) {
    g_svcStatusHandle =
        RegisterServiceCtrlHandlerExW(SERVICE_NAME, SvcCtrlHandlerEx, NULL);
    if (!g_svcStatusHandle) return;

    g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    SvcReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_svcStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_svcStopEvent) {
        SvcReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    SvcReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    /* Launch the GUI in every active session right away */
    LaunchGuiInAllSessions();

    /* Block until SERVICE_CONTROL_STOP */
    WaitForSingleObject(g_svcStopEvent, INFINITE);

    CloseHandle(g_svcStopEvent);
    SvcReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

// ============================================================
// install / uninstall helpers (run from an elevated prompt)
// ============================================================

static int InstallService(void) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return 1;

    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    SC_HANDLE hSvc = CreateServiceW(
        hSCM, SERVICE_NAME, L"Ziovpontvrs Service",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        path, NULL, NULL, NULL, NULL, NULL);

    if (hSvc) {
        SERVICE_DESCRIPTIONW desc = {};
        desc.lpDescription = const_cast<LPWSTR>(L"Ziovpontvrs background service");
        ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    return hSvc ? 0 : 1;
}

static int UninstallService(void) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return 1;

    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, DELETE);
    BOOL ok = FALSE;
    if (hSvc) {
        ok = DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    return ok ? 0 : 1;
}

// ============================================================
// Entry point
// ============================================================

int wmain(int argc, wchar_t *argv[]) {
    if (argc >= 2) {
        if (_wcsicmp(argv[1], L"install")   == 0) return InstallService();
        if (_wcsicmp(argv[1], L"uninstall") == 0) return UninstallService();
    }

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), SvcMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcherW(table);
    return 0;
}
