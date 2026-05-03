#include "jwt_util.h"

#include "json_mini.h"

#include <string>

namespace {

int DecodeBase64Char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

}  /* anonymous namespace */

namespace jwt {

std::string Base64UrlDecode(const std::string& input) {
    std::string out;
    out.reserve(input.size() * 3 / 4);

    int buf = 0, bits = 0;
    for (char c : input) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = DecodeBase64Char(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((buf >> bits) & 0xFF);
        }
    }
    return out;
}

int64_t GetExpiration(const std::string& token) {
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return 0;
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return 0;

    std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string payload     = Base64UrlDecode(payload_b64);

    int64_t exp = 0;
    if (!jsonmini::GetInt64(payload, "exp", exp)) return 0;
    return exp;
}

}  /* namespace jwt */
