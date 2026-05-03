#pragma once

#include <windows.h>

#include <string>

namespace http {

struct Response {
    DWORD       status_code = 0;   /* HTTP status (200, 401, ...) or 0 on transport failure */
    std::string body;
};

/* Synchronous HTTPS POST / GET. `path` is server-relative (e.g. "/api/foo").
 * If `bearer_token` is non-null, an Authorization: Bearer header is added.
 * Returns true only if the transport call succeeded — the caller must still
 * inspect `status_code`. */
bool Post(const wchar_t* path,
          const std::string& json_body,
          const std::string* bearer_token,
          Response& out);

bool Get(const wchar_t* path,
         const std::string* bearer_token,
         Response& out);

}  /* namespace http */
