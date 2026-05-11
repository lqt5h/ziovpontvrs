#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <aclapi.h>
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

extern "C" {
#include "rpc_iface.h"
}
#include "rpc_common.h"
#include "auth_state.h"
#include "av_engine.h"

#include <string>

// ============================================================
// Constants
// ============================================================

#define SERVICE_NAME L"ZiovpontvrsSvc"

// ============================================================
// Globals
// ============================================================

static SERVICE_STATUS        g_svcStatus       = {};
static SERVICE_STATUS_HANDLE g_svcStatusHandle = NULL;

static CRITICAL_SECTION      g_guiLock;
static std::vector<HANDLE>   g_guiProcs;

// ============================================================
// RPC — MIDL allocator hooks + server implementation
// ============================================================

extern "C" void * __RPC_USER MIDL_user_allocate(size_t size) {
    return malloc(size);
}

extern "C" void __RPC_USER MIDL_user_free(void *p) {
    free(p);
}

static BOOL ConfirmShutdownOnSecureDesktop(void);

extern "C" void RpcShutdown(void) {
    if (!ConfirmShutdownOnSecureDesktop()) return;
    RpcMgmtStopServerListening(NULL);
}

/* ------------------------------------------------------------
 * Auth RPC — all signatures match the widl-generated server stubs in
 * rpc_iface.h (see src/rpc_iface.idl). Nothing here exposes the raw JWT
 * tokens or the license ticket to callers. */

extern "C" long RpcLogin(const wchar_t *username, const wchar_t *password) {
    return auth::Login(username, password);
}

extern "C" long RpcLogout(void) {
    return auth::Logout();
}

extern "C" long RpcGetCurrentUser(long *isAuthenticated, wchar_t **username) {
    if (!isAuthenticated || !username) return auth::kErrInternal;

    *isAuthenticated = auth::IsAuthenticated() ? 1 : 0;

    WCHAR tmp[256] = L"";
    if (*isAuthenticated) auth::GetUsername(tmp, 256);

    size_t nbytes = (wcslen(tmp) + 1) * sizeof(WCHAR);
    WCHAR *buf = static_cast<WCHAR *>(MIDL_user_allocate(nbytes));
    if (!buf) return auth::kErrInternal;
    memcpy(buf, tmp, nbytes);
    *username = buf;
    return auth::kOk;
}

extern "C" long RpcGetLicenseStatus(long *hasLicense, hyper *expirationFileTime) {
    if (!hasLicense || !expirationFileTime) return auth::kErrInternal;
    *hasLicense         = auth::HasLicense() ? 1 : 0;
    *expirationFileTime = 0;
    if (*hasLicense) {
        LONGLONG ft = 0;
        auth::GetLicenseExpiration(&ft);
        *expirationFileTime = ft;
    }
    return auth::kOk;
}

extern "C" long RpcActivateProduct(const wchar_t *activationCode) {
    return auth::Activate(activationCode);
}

extern "C" long RpcAntivirusScan(void) {
    return auth::CheckAntivirusAllowed();
}

static WCHAR *AllocRpcString(const std::wstring& s) {
    size_t nbytes = (s.size() + 1) * sizeof(WCHAR);
    WCHAR *buf = static_cast<WCHAR *>(MIDL_user_allocate(nbytes));
    if (buf) memcpy(buf, s.c_str(), nbytes);
    return buf;
}

static std::wstring ToWideStr(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring w(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

extern "C" long RpcScanFile(const wchar_t *filePath, wchar_t **resultMessage) {
    if (!filePath || !resultMessage) return auth::kErrInternal;
    long gate = auth::CheckAntivirusAllowed();
    if (gate != auth::kOk) {
        *resultMessage = AllocRpcString(L"\x041D\x0435\x0442 \x043B\x0438\x0446\x0435\x043D\x0437\x0438\x0438");
        return gate;
    }

    av::ScanReport report = av::ScanFile(filePath);
    std::wstring msg;
    if (report.result == av::SCAN_MALICIOUS) {
        msg = L"\x0423\x0433\x0440\x043E\x0437\x0430 \x043E\x0431\x043D\x0430\x0440\x0443\x0436\x0435\x043D\x0430: ";
        msg += filePath;
    } else if (report.result == av::SCAN_ERROR) {
        msg = L"\x041E\x0448\x0438\x0431\x043A\x0430 \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x044F: ";
        msg += filePath;
    } else {
        msg = L"\x0427\x0438\x0441\x0442\x043E: ";
        msg += filePath;
    }
    *resultMessage = AllocRpcString(msg);
    return auth::kOk;
}

extern "C" long RpcScanDirectory(const wchar_t *dirPath, wchar_t **resultMessage) {
    if (!dirPath || !resultMessage) return auth::kErrInternal;
    long gate = auth::CheckAntivirusAllowed();
    if (gate != auth::kOk) {
        *resultMessage = AllocRpcString(L"\x041D\x0435\x0442 \x043B\x0438\x0446\x0435\x043D\x0437\x0438\x0438");
        return gate;
    }

    auto reports = av::ScanDirectory(dirPath);
    int total = 0, threats = 0, errors = 0;
    std::wstring details;
    for (const auto& r : reports) {
        total++;
        if (r.result == av::SCAN_MALICIOUS) {
            threats++;
            details += L"\x0423\x0433\x0440\x043E\x0437\x0430: ";
            details += r.filePath;
            details += L"\n";
        } else if (r.result == av::SCAN_ERROR) {
            errors++;
        }
    }

    WCHAR summary[512];
    swprintf(summary, 512,
             L"\x041F\x0440\x043E\x0432\x0435\x0440\x0435\x043D\x043E: %d, "
             L"\x0443\x0433\x0440\x043E\x0437: %d, "
             L"\x043E\x0448\x0438\x0431\x043E\x043A: %d",
             total, threats, errors);
    std::wstring msg = summary;
    if (!details.empty()) {
        msg += L"\n";
        msg += details;
    }
    *resultMessage = AllocRpcString(msg);
    return auth::kOk;
}

extern "C" long RpcGetAvDatabaseInfo(long *recordCount, wchar_t **releaseDate) {
    if (!recordCount || !releaseDate) return auth::kErrInternal;
    *recordCount = av::GetRecordCount();
    std::string date = av::GetReleaseDate();
    if (date.empty()) date = "-";
    *releaseDate = AllocRpcString(ToWideStr(date));
    return auth::kOk;
}

// ============================================================
// DACL — deny PROCESS_TERMINATE to Everyone (including admins)
// ============================================================

static void ProtectProcess(HANDLE hProcess) {
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSid = NULL;
    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &pEveryoneSid))
        return;

    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = PROCESS_TERMINATE;
    ea.grfAccessMode        = DENY_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = (LPWSTR)pEveryoneSid;

    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                    NULL, NULL, &pOldDacl, NULL, &pSD);

    PACL pNewDacl = NULL;
    if (SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl) == ERROR_SUCCESS && pNewDacl) {
        SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        NULL, NULL, pNewDacl, NULL);
        LocalFree(pNewDacl);
    }

    if (pSD) LocalFree(pSD);
    FreeSid(pEveryoneSid);
}

// ============================================================
// Secure Desktop — shutdown confirmation via WTSSendMessage
// ============================================================

static DWORD GetActiveSessionId(void) {
    PWTS_SESSION_INFOW pSessions = NULL;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                               &pSessions, &count))
        return 0;
    DWORD sid = 0;
    for (DWORD i = 0; i < count; i++) {
        if (pSessions[i].State == WTSActive && pSessions[i].SessionId != 0) {
            sid = pSessions[i].SessionId;
            break;
        }
    }
    WTSFreeMemory(pSessions);
    return sid;
}

static BOOL ConfirmShutdownOnSecureDesktop(void) {
    DWORD sessionId = GetActiveSessionId();
    if (sessionId == 0) return TRUE;

    const WCHAR title[]   = L"Ziovpontvrs";
    const WCHAR message[] = L"\x041E\x0441\x0442\x0430\x043D\x043E\x0432\x0438\x0442\x044C"
                            L" \x0441\x043B\x0443\x0436\x0431\x0443 Ziovpontvrs?";

    DWORD response = 0;
    BOOL ok = WTSSendMessageW(
        WTS_CURRENT_SERVER_HANDLE,
        sessionId,
        const_cast<LPWSTR>(title),
        (DWORD)(wcslen(title) * sizeof(WCHAR)),
        const_cast<LPWSTR>(message),
        (DWORD)(wcslen(message) * sizeof(WCHAR)),
        MB_YESNO | MB_ICONQUESTION,
        0,
        &response,
        TRUE);

    if (!ok) return TRUE;
    return response == IDYES;
}

// ============================================================
// GUI process bookkeeping
// ============================================================

static void TrackGuiProc(HANDLE hProc) {
    EnterCriticalSection(&g_guiLock);
    g_guiProcs.push_back(hProc);
    LeaveCriticalSection(&g_guiLock);
}

static void TerminateTrackedGuiProcs(void) {
    EnterCriticalSection(&g_guiLock);
    for (HANDLE h : g_guiProcs) {
        TerminateProcess(h, 0);
        CloseHandle(h);
    }
    g_guiProcs.clear();
    LeaveCriticalSection(&g_guiLock);
}

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
    if (sessionId == 0) return;                 /* never session 0 */

    WCHAR guiPath[MAX_PATH];
    if (!GetGuiExePath(guiPath, MAX_PATH)) return;

    WCHAR cmdLine[MAX_PATH + 32];
    swprintf(cmdLine, sizeof(cmdLine) / sizeof(WCHAR),
             L"\"%ls\" --silent", guiPath);

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
    BOOL ok = CreateProcessAsUserW(
        hDupToken, NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        pEnv, NULL, &si, &pi);

    if (ok) {
        if (pi.hThread)  CloseHandle(pi.hThread);
        if (pi.hProcess) {
            ProtectProcess(pi.hProcess);
            TrackGuiProc(pi.hProcess);
        }
    }

    if (pEnv) DestroyEnvironmentBlock(pEnv);
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
        if (pSessions[i].SessionId == 0)      continue;
        if (pSessions[i].State != WTSActive)  continue;
        LaunchGuiInSession(pSessions[i].SessionId);
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

    /* Intentionally do NOT advertise SERVICE_ACCEPT_STOP or
     * SERVICE_ACCEPT_SHUTDOWN — the service is stopped exclusively through
     * the RPC interface. */
    if (state == SERVICE_START_PENDING)
        g_svcStatus.dwControlsAccepted = 0;
    else
        g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;

    g_svcStatus.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;

    SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
}

// ============================================================
// Service control handler
// ============================================================

static DWORD WINAPI SvcCtrlHandlerEx(DWORD dwControl, DWORD dwEventType,
                                     LPVOID lpEventData, LPVOID /*lpContext*/) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        /* Ignored by design — shutdown is driven only by the RPC call. */
        return ERROR_CALL_NOT_IMPLEMENTED;

    case SERVICE_CONTROL_SESSIONCHANGE:
        if (dwEventType == WTS_SESSION_LOGON) {
            auto *pNotif = reinterpret_cast<WTSSESSION_NOTIFICATION *>(lpEventData);
            if (pNotif && pNotif->dwSessionId != 0) {
                Sleep(3000);                    /* let the session initialise */
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
// RPC server boot / teardown
// ============================================================

static RPC_STATUS StartRpcServer(void) {
    RPC_STATUS rs = RpcServerUseProtseqEpW(
        ZIOVPONTVRS_RPC_PROTSEQ,
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        ZIOVPONTVRS_RPC_ENDPOINT,
        NULL);
    if (rs != RPC_S_OK && rs != RPC_S_DUPLICATE_ENDPOINT) return rs;

    return RpcServerRegisterIf(ZiovpontvrsRpc_v1_0_s_ifspec, NULL, NULL);
}

static void StopRpcServer(void) {
    RpcServerUnregisterIf(ZiovpontvrsRpc_v1_0_s_ifspec, NULL, FALSE);
}

// ============================================================
// ServiceMain
// ============================================================

static void WINAPI SvcMain(DWORD /*argc*/, LPWSTR * /*argv*/) {
    InitializeCriticalSection(&g_guiLock);

    g_svcStatusHandle =
        RegisterServiceCtrlHandlerExW(SERVICE_NAME, SvcCtrlHandlerEx, NULL);
    if (!g_svcStatusHandle) {
        DeleteCriticalSection(&g_guiLock);
        return;
    }

    g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    SvcReportStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    RPC_STATUS rs = StartRpcServer();
    if (rs != RPC_S_OK) {
        SvcReportStatus(SERVICE_STOPPED, rs, 0);
        DeleteCriticalSection(&g_guiLock);
        return;
    }

    /* Bring up the auth / license state machine — starts the background
     * refresh threads. They idle until a user logs in. */
    auth::Init();
    av::InitDatabase();
    av::LoadDatabaseFromDisk();

    SvcReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    ProtectProcess(GetCurrentProcess());

    /* Launch the GUI in every active session right away. */
    LaunchGuiInAllSessions();

    /* Block until a client calls RpcShutdown(). */
    RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);

    av::ShutdownDatabase();
    auth::Shutdown();
    StopRpcServer();

    /* Kill every GUI instance we launched. */
    TerminateTrackedGuiProcs();

    DeleteCriticalSection(&g_guiLock);

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
