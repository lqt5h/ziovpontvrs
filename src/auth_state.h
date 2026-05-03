#pragma once

#include <windows.h>

/* Thread-safe in-memory store for:
 *   - JWT access / refresh tokens (+ expirations),
 *   - the authenticated user's login,
 *   - the license ticket (+ expiration).
 *
 * Nothing here is ever persisted to disk or exposed to RPC clients — RPC
 * returns only metadata (username, "has license", expiration time). */

namespace auth {

enum ResultCode : long {
    kOk                   = 0,
    kErrUnauthenticated   = 1,
    kErrNetwork           = 2,
    kErrBadCredentials    = 3,
    kErrLicenseMissing    = 4,
    kErrActivationFailed  = 5,
    kErrInternal          = 6,
};

void Init();
void Shutdown();

/* Auth */
long Login (const wchar_t* username, const wchar_t* password);
long Logout();
bool IsAuthenticated();

/* Fills `buf` with the current username. Returns false if unauthenticated
 * or the buffer is too small. `bufChars` is the wchar_t count of `buf`. */
bool GetUsername(wchar_t* buf, size_t bufChars);

/* License */
long Activate(const wchar_t* activationCode);
bool HasLicense();
bool GetLicenseExpiration(LONGLONG* outFileTime);  /* FILETIME as int64 */

/* Antivirus gate — returns kOk iff a valid license ticket is held. */
long CheckAntivirusAllowed();

}  /* namespace auth */
