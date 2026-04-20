#pragma once

#include <cstdint>
#include <string>

namespace jwt {

std::string Base64UrlDecode(const std::string& input);

/* Extract the `exp` claim (seconds since Unix epoch). Returns 0 on failure. */
int64_t GetExpiration(const std::string& token);

}  /* namespace jwt */
