#pragma once

/* Placeholder API endpoints. The service communicates with the Web service
 * over HTTPS (WinHTTP) using JSON payloads. Replace the host / paths below
 * with the real URLs provided by the deployment. */

#define API_HOST   L"api.ziovpontvrs.example"
#define API_PORT   INTERNET_DEFAULT_HTTPS_PORT

/* Auth */
#define API_PATH_LOGIN            L"/api/auth/login"     /* POST { username, password } -> { access, refresh } */
#define API_PATH_REFRESH          L"/api/auth/refresh"   /* POST { refresh }            -> { access, refresh } */

/* License */
#define API_PATH_LICENSE_STATUS   L"/api/license/status"    /* GET  Bearer -> { ticket, validTo }            */
#define API_PATH_LICENSE_ACTIVATE L"/api/license/activate"  /* POST Bearer + { code } -> { ticket? }         */

/* Refresh safety margin — renew tokens / ticket this many seconds before
 * their actual expiration. */
#define API_REFRESH_SKEW_SEC      30
