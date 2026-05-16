#pragma once

#define API_HOST   L"localhost"
#define API_PORT   8443

#define API_PATH_LOGIN            L"/auth/login"
#define API_PATH_REFRESH          L"/auth/refresh"

#define API_PATH_LICENSE_CHECK    L"/api/licenses/check"
#define API_PATH_LICENSE_ACTIVATE L"/api/licenses/activate"

#define API_DEFAULT_PRODUCT_ID    1

#define API_PATH_SIGNATURES       L"/api/signatures"

#define API_PATH_BINARY_SIGNATURES_FULL    L"/api/binary/signatures/full"
#define API_PATH_BINARY_SIGNATURES_BY_IDS  L"/api/binary/signatures/by-ids"

#define API_REFRESH_SKEW_SEC      30

#define AV_UPDATE_INTERVAL_SEC    (30 * 60)
