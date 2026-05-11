#include "http_client.h"

#include "api_config.h"

#include <windows.h>
#include <winhttp.h>

#include <string>
#include <vector>

namespace {

/* Narrow (UTF-8) <-> wide conversions. WinHTTP wants wide strings for
 * headers; our JSON bodies are UTF-8. */

std::wstring Widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                                static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                        out.data(), n);
    return out;
}

struct HandleGuard {
    HINTERNET h;
    explicit HandleGuard(HINTERNET hh) : h(hh) {}
    ~HandleGuard() { if (h) WinHttpCloseHandle(h); }
    HandleGuard(const HandleGuard&)            = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
};

bool DoRequest(const wchar_t* verb,
               const wchar_t* path,
               const std::string& body,
               const std::string* bearer_token,
               http::Response& out) {
    HINTERNET hSession = WinHttpOpen(
        L"ZiovpontvrsSvc/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    HandleGuard gSession(hSession);

    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) return false;
    HandleGuard gConnect(hConnect);

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, verb, path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) return false;
    HandleGuard gRequest(hRequest);

    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     &secFlags, sizeof(secFlags));

    std::wstring headers = L"Content-Type: application/json\r\nAccept: */*\r\n";
    if (bearer_token && !bearer_token->empty()) {
        headers += L"Authorization: Bearer ";
        headers += Widen(*bearer_token);
        headers += L"\r\n";
    }

    LPVOID  pBody   = body.empty() ? WINHTTP_NO_REQUEST_DATA
                                   : const_cast<char*>(body.data());
    DWORD   nBody   = static_cast<DWORD>(body.size());

    BOOL ok = WinHttpSendRequest(
        hRequest,
        headers.c_str(), static_cast<DWORD>(-1L),
        pBody, nBody, nBody, 0);
    if (!ok) return false;

    if (!WinHttpReceiveResponse(hRequest, nullptr)) return false;

    DWORD status     = 0;
    DWORD statusSize = sizeof(status);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                        WINHTTP_NO_HEADER_INDEX);
    out.status_code = status;

    out.body.clear();
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) return false;
        if (avail == 0) break;

        std::vector<char> chunk(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, chunk.data(), avail, &read)) return false;
        if (read == 0) break;
        out.body.append(chunk.data(), read);
    }
    return true;
}

}  /* anonymous namespace */

namespace http {

bool Post(const wchar_t* path, const std::string& body,
          const std::string* bearer_token, Response& out) {
    return DoRequest(L"POST", path, body, bearer_token, out);
}

bool Get(const wchar_t* path, const std::string* bearer_token, Response& out) {
    return DoRequest(L"GET", path, std::string(), bearer_token, out);
}

}  /* namespace http */
