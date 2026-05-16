#include "auth_state.h"

#include "api_config.h"
#include "av_engine.h"
#include "http_client.h"
#include "json_mini.h"
#include "jwt_util.h"

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <ctime>
#include <string>
#include <vector>

namespace {

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

CRITICAL_SECTION g_lock;

std::string  g_access;
std::string  g_refresh;
int64_t      g_access_exp  = 0;    /* Unix time */
int64_t      g_refresh_exp = 0;

std::wstring g_username;

std::string  g_ticket;             /* opaque license ticket (never leaves process) */
int64_t      g_ticket_exp = 0;

HANDLE g_stopEvent    = nullptr;   /* signals both refresh threads to exit */
HANDLE g_wakeEvent    = nullptr;   /* wakes refresh threads after state changes */
HANDLE g_tokenThread  = nullptr;
HANDLE g_licThread    = nullptr;
HANDLE g_avThread     = nullptr;   /* simulated antivirus background task */
HANDLE g_avStopEvent  = nullptr;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

class Guard {
public:
    Guard()  { EnterCriticalSection(&g_lock); }
    ~Guard() { LeaveCriticalSection(&g_lock); }
    Guard(const Guard&)            = delete;
    Guard& operator=(const Guard&) = delete;
};

int64_t NowUnix() {
    return static_cast<int64_t>(std::time(nullptr));
}

/* UTF-16 -> UTF-8 (for JSON request bodies) */
std::string ToUtf8(const wchar_t* ws) {
    if (!ws || !*ws) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring w(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

/* Extremely small JSON escape — we only stuff already-validated usernames,
 * passwords and activation codes in request bodies. */
std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    wsprintfA(buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

int64_t ParseIsoDate(const std::string& date) {
    int y = 0, m = 0, d = 0;
    if (sscanf(date.c_str(), "%d-%d-%d", &y, &m, &d) != 3) return 0;
    struct tm t = {};
    t.tm_year = y - 1900;
    t.tm_mon  = m - 1;
    t.tm_mday = d;
    t.tm_hour = 23;
    t.tm_min  = 59;
    t.tm_sec  = 59;
    return static_cast<int64_t>(mktime(&t));
}

int64_t TicketExpirationFromBody(const std::string& body) {
    std::string expDate;
    if (jsonmini::GetString(body, "expirationDate", expDate)) {
        int64_t exp = ParseIsoDate(expDate);
        if (exp > 0) return exp;
    }
    int64_t exp = 0;
    if (jsonmini::GetInt64(body, "expiresAt", exp)) return exp;
    if (jsonmini::GetInt64(body, "validTo",   exp)) return exp;
    return 0;
}

std::string GetDeviceMac() {
    ULONG size = 15000;
    std::vector<BYTE> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;

    DWORD rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size);
    }
    if (rc != ERROR_SUCCESS) return "00:00:00:00:00:00";

    for (auto* a = addrs; a; a = a->Next) {
        if (a->PhysicalAddressLength == 6 &&
            a->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     a->PhysicalAddress[0], a->PhysicalAddress[1],
                     a->PhysicalAddress[2], a->PhysicalAddress[3],
                     a->PhysicalAddress[4], a->PhysicalAddress[5]);
            return mac;
        }
    }
    return "00:00:00:00:00:00";
}

std::string GetDeviceName() {
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(name, &sz))
        return ToUtf8(name);
    return "unknown";
}

/* ------------------------------------------------------------------ */
/* Antivirus worker — ticks while a license is held                   */
/* ------------------------------------------------------------------ */

DWORD WINAPI AntivirusWorker(LPVOID /*ctx*/) {
    DWORD interval = AV_UPDATE_INTERVAL_SEC * 1000;
    while (WaitForSingleObject(g_avStopEvent, interval) == WAIT_TIMEOUT) {
        std::string token;
        {
            Guard g;
            token = g_access;
        }
        if (!token.empty())
            av::UpdateDatabase(token);
    }
    return 0;
}

void StartAntivirus() {
    if (g_avThread) return;

    std::string token;
    {
        Guard g;
        token = g_access;
    }
    if (!token.empty())
        av::UpdateDatabase(token);

    g_avStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_avThread    = CreateThread(nullptr, 0, AntivirusWorker, nullptr, 0, nullptr);
}

void StopAntivirus() {
    if (!g_avThread) return;
    SetEvent(g_avStopEvent);
    WaitForSingleObject(g_avThread, 10000);
    CloseHandle(g_avThread);
    CloseHandle(g_avStopEvent);
    g_avThread    = nullptr;
    g_avStopEvent = nullptr;
}

/* ------------------------------------------------------------------ */
/* HTTP operations (called with g_lock NOT held)                       */
/* ------------------------------------------------------------------ */

bool DoLoginRequest(const std::string& userU8,
                    const std::string& passU8,
                    std::string& outAccess,
                    std::string& outRefresh) {
    std::string body =
        std::string("{\"username\":\"") + JsonEscape(userU8) +
                   "\",\"password\":\"" + JsonEscape(passU8) + "\"}";

    http::Response resp;
    if (!http::Post(API_PATH_LOGIN, body, nullptr, resp)) return false;
    if (resp.status_code != 200) return false;

    if (!jsonmini::GetString(resp.body, "accessToken",  outAccess))  return false;
    if (!jsonmini::GetString(resp.body, "refreshToken", outRefresh)) return false;
    return true;
}

bool DoRefreshRequest(const std::string& refresh,
                      std::string& outAccess,
                      std::string& outRefresh) {
    std::string body = std::string("{\"refreshToken\":\"") + JsonEscape(refresh) + "\"}";

    http::Response resp;
    if (!http::Post(API_PATH_REFRESH, body, nullptr, resp)) return false;
    if (resp.status_code != 200) return false;

    if (!jsonmini::GetString(resp.body, "accessToken",  outAccess))  return false;
    if (!jsonmini::GetString(resp.body, "refreshToken", outRefresh)) return false;
    return true;
}

bool DoLicenseCheckRequest(const std::string& access,
                           std::string& outTicket,
                           int64_t& outExp) {
    std::string mac  = GetDeviceMac();
    char pidBuf[32];
    snprintf(pidBuf, sizeof(pidBuf), "%d", API_DEFAULT_PRODUCT_ID);

    std::string body =
        std::string("{\"deviceMac\":\"") + JsonEscape(mac) +
        "\",\"productId\":" + pidBuf + "}";

    http::Response resp;
    if (!http::Post(API_PATH_LICENSE_CHECK, body, &access, resp)) return false;
    if (resp.status_code == 404) { outTicket.clear(); outExp = 0; return true; }
    if (resp.status_code != 200) return false;

    if (!jsonmini::GetString(resp.body, "signature", outTicket)) {
        outTicket.clear();
    }
    outExp = TicketExpirationFromBody(resp.body);
    return !outTicket.empty();
}

bool DoActivateRequest(const std::string& access,
                       const std::string& codeU8,
                       std::string& outTicket,
                       int64_t& outExp) {
    std::string mac  = GetDeviceMac();
    std::string name = GetDeviceName();

    std::string body =
        std::string("{\"activationKey\":\"") + JsonEscape(codeU8) +
        "\",\"deviceMac\":\"" + JsonEscape(mac) +
        "\",\"deviceName\":\"" + JsonEscape(name) + "\"}";

    http::Response resp;
    if (!http::Post(API_PATH_LICENSE_ACTIVATE, body, &access, resp)) return false;
    if (resp.status_code != 200) return false;

    outTicket.clear();
    outExp = 0;
    if (jsonmini::GetString(resp.body, "signature", outTicket)) {
        outExp = TicketExpirationFromBody(resp.body);
        return true;
    }
    return DoLicenseCheckRequest(access, outTicket, outExp);
}

/* ------------------------------------------------------------------ */
/* Refresh threads                                                    */
/* ------------------------------------------------------------------ */

/* Wait either for the stop event, the wake event, or `ms` milliseconds.
 * Returns: 0 = stop, 1 = wake, 2 = timeout. */
int WaitOrStop(DWORD ms) {
    HANDLE handles[2] = { g_stopEvent, g_wakeEvent };
    DWORD r = WaitForMultipleObjects(2, handles, FALSE, ms);
    if (r == WAIT_OBJECT_0)     return 0;
    if (r == WAIT_OBJECT_0 + 1) { ResetEvent(g_wakeEvent); return 1; }
    return 2;
}

DWORD WINAPI TokenRefreshWorker(LPVOID /*ctx*/) {
    for (;;) {
        std::string refresh;
        int64_t     accessExp = 0;
        {
            Guard g;
            refresh    = g_refresh;
            accessExp  = g_access_exp;
        }

        DWORD wait_ms;
        if (refresh.empty() || accessExp == 0) {
            wait_ms = 30 * 60 * 1000;    /* idle — no session */
        } else {
            int64_t now   = NowUnix();
            int64_t delta = accessExp - API_REFRESH_SKEW_SEC - now;
            if (delta < 0) delta = 0;
            if (delta > 24 * 3600) delta = 24 * 3600;
            wait_ms = static_cast<DWORD>(delta * 1000);
        }

        int w = WaitOrStop(wait_ms);
        if (w == 0) return 0;
        if (w == 1) continue;            /* state changed — recompute */

        /* Timeout — time to refresh. */
        std::string cur_refresh;
        {
            Guard g;
            cur_refresh = g_refresh;
        }
        if (cur_refresh.empty()) continue;

        std::string newAccess, newRefresh;
        if (!DoRefreshRequest(cur_refresh, newAccess, newRefresh)) {
            /* Transient failure — retry after a minute. */
            if (WaitOrStop(60 * 1000) == 0) return 0;
            continue;
        }

        {
            Guard g;
            /* If the user logged out / re-logged while we were in flight,
             * discard the refreshed pair — the new session owns its own
             * tokens. */
            if (g_refresh != cur_refresh) continue;
            g_access      = newAccess;
            g_refresh     = newRefresh;
            g_access_exp  = jwt::GetExpiration(newAccess);
            g_refresh_exp = jwt::GetExpiration(newRefresh);
        }
    }
}

DWORD WINAPI LicenseRefreshWorker(LPVOID /*ctx*/) {
    for (;;) {
        int64_t ticketExp;
        bool    haveTicket;
        bool    haveAccess;
        {
            Guard g;
            ticketExp  = g_ticket_exp;
            haveTicket = !g_ticket.empty();
            haveAccess = !g_access.empty();
        }

        DWORD wait_ms;
        if (!haveAccess) {
            wait_ms = 30 * 60 * 1000;
        } else if (!haveTicket || ticketExp == 0) {
            wait_ms = 5 * 60 * 1000;     /* unknown — probe every 5 min */
        } else {
            int64_t now   = NowUnix();
            int64_t delta = ticketExp - API_REFRESH_SKEW_SEC - now;
            if (delta < 0) delta = 0;
            if (delta > 24 * 3600) delta = 24 * 3600;
            wait_ms = static_cast<DWORD>(delta * 1000);
        }

        int w = WaitOrStop(wait_ms);
        if (w == 0) return 0;
        if (w == 1) continue;

        std::string access;
        {
            Guard g;
            access = g_access;
        }
        if (access.empty()) continue;

        std::string newTicket;
        int64_t     newExp = 0;
        bool ok = DoLicenseCheckRequest(access, newTicket, newExp);
        if (!ok) {
            if (WaitOrStop(60 * 1000) == 0) return 0;
            continue;
        }

        bool licenseGainedOrKept;
        {
            Guard g;
            /* Same safety net as the token worker: drop the refreshed
             * ticket if the session changed under our feet. */
            if (g_access != access) continue;
            g_ticket     = newTicket;
            g_ticket_exp = newExp;
            licenseGainedOrKept = !g_ticket.empty();
        }

        if (licenseGainedOrKept) StartAntivirus();
        else                     StopAntivirus();
    }
}

}  /* anonymous namespace */

/* ============================================================ */
/* Public API                                                    */
/* ============================================================ */

namespace auth {

void Init() {
    InitializeCriticalSection(&g_lock);
    g_stopEvent   = CreateEventW(nullptr, TRUE,  FALSE, nullptr);
    g_wakeEvent   = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_tokenThread = CreateThread (nullptr, 0, TokenRefreshWorker,   nullptr, 0, nullptr);
    g_licThread   = CreateThread (nullptr, 0, LicenseRefreshWorker, nullptr, 0, nullptr);
}

void Shutdown() {
    if (g_stopEvent) SetEvent(g_stopEvent);

    HANDLE workers[2] = { g_tokenThread, g_licThread };
    DWORD  nWorkers   = 0;
    if (g_tokenThread) workers[nWorkers++] = g_tokenThread;
    if (g_licThread)   workers[nWorkers++] = g_licThread;
    if (nWorkers) WaitForMultipleObjects(nWorkers, workers, TRUE, 10000);

    if (g_tokenThread) { CloseHandle(g_tokenThread); g_tokenThread = nullptr; }
    if (g_licThread)   { CloseHandle(g_licThread);   g_licThread   = nullptr; }

    StopAntivirus();

    if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
    if (g_wakeEvent) { CloseHandle(g_wakeEvent); g_wakeEvent = nullptr; }

    DeleteCriticalSection(&g_lock);
}

long Login(const wchar_t* username, const wchar_t* password) {
    if (!username || !password) return kErrInternal;

    std::string userU8 = ToUtf8(username);
    std::string passU8 = ToUtf8(password);

    std::string access, refresh;
    if (!DoLoginRequest(userU8, passU8, access, refresh)) {
        return kErrBadCredentials;
    }

    {
        Guard g;
        g_access      = access;
        g_refresh     = refresh;
        g_access_exp  = jwt::GetExpiration(access);
        g_refresh_exp = jwt::GetExpiration(refresh);
        g_username    = std::wstring(username);
    }
    SetEvent(g_wakeEvent);    /* let both workers recompute their timings */
    return kOk;
}

long Logout() {
    {
        Guard g;
        g_access.clear();
        g_refresh.clear();
        g_access_exp  = 0;
        g_refresh_exp = 0;
        g_username.clear();
        g_ticket.clear();          /* spec: drop ticket at logout */
        g_ticket_exp  = 0;
    }
    StopAntivirus();
    SetEvent(g_wakeEvent);
    return kOk;
}

bool IsAuthenticated() {
    Guard g;
    return !g_access.empty();
}

bool GetUsername(wchar_t* buf, size_t bufChars) {
    if (!buf || bufChars == 0) return false;
    Guard g;
    if (g_username.empty()) { buf[0] = L'\0'; return false; }
    if (g_username.size() + 1 > bufChars) return false;
    wcscpy(buf, g_username.c_str());
    return true;
}

long Activate(const wchar_t* code) {
    std::string access;
    {
        Guard g;
        if (g_access.empty()) return kErrUnauthenticated;
        access = g_access;
    }

    std::string codeU8 = ToUtf8(code);
    std::string ticket;
    int64_t     exp = 0;
    if (!DoActivateRequest(access, codeU8, ticket, exp)) {
        return kErrActivationFailed;
    }
    if (ticket.empty()) return kErrActivationFailed;

    {
        Guard g;
        g_ticket     = ticket;
        g_ticket_exp = exp;
    }
    StartAntivirus();
    SetEvent(g_wakeEvent);
    return kOk;
}

bool HasLicense() {
    Guard g;
    return !g_ticket.empty();
}

bool GetLicenseExpiration(LONGLONG* outFileTime) {
    if (!outFileTime) return false;
    int64_t exp;
    {
        Guard g;
        if (g_ticket.empty() || g_ticket_exp == 0) return false;
        exp = g_ticket_exp;
    }
    /* Unix time (s) -> FILETIME (100-ns intervals since 1601-01-01). */
    const LONGLONG kUnixEpochInFileTime = 116444736000000000LL;
    *outFileTime = kUnixEpochInFileTime + exp * 10000000LL;
    return true;
}

long CheckAntivirusAllowed() {
    return HasLicense() ? kOk : kErrLicenseMissing;
}

}  /* namespace auth */
