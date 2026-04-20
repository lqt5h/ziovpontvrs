#pragma once

#include <string>
#include <cstdint>

/* Intentionally tiny JSON extractor for flat response bodies. Not a general
 * parser — it looks up `"key"`, skips whitespace and the colon, then reads
 * the immediately-following string or integer value. */

namespace jsonmini {

bool GetString(const std::string& json, const char* key, std::string& out);
bool GetInt64 (const std::string& json, const char* key, int64_t&    out);

}  /* namespace jsonmini */
