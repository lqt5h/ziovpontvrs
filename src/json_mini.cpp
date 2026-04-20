#include "json_mini.h"

#include <cctype>
#include <cstdlib>
#include <string>

namespace {

/* Find the first occurrence of "key" (quoted) that is used as an object key
 * — i.e. followed (after whitespace) by a colon. Returns index past the
 * colon, or std::string::npos if not found. */
size_t FindKeyValueStart(const std::string& s, const char* key) {
    std::string needle = "\"";
    needle += key;
    needle += "\"";

    size_t pos = 0;
    while ((pos = s.find(needle, pos)) != std::string::npos) {
        size_t after = pos + needle.size();
        size_t i = after;
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) i++;
        if (i < s.size() && s[i] == ':') return i + 1;
        pos = after;
    }
    return std::string::npos;
}

std::string DecodeJsonString(const std::string& s, size_t& i) {
    /* s[i] is the opening quote */
    std::string out;
    i++;                              /* skip opening quote */
    while (i < s.size() && s[i] != '"') {
        char c = s[i];
        if (c == '\\' && i + 1 < s.size()) {
            char esc = s[i + 1];
            switch (esc) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'n':  out += '\n'; break;
                case 't':  out += '\t'; break;
                case 'r':  out += '\r'; break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                default:   out += esc;  break;  /* \uXXXX not handled */
            }
            i += 2;
        } else {
            out += c;
            i++;
        }
    }
    if (i < s.size()) i++;            /* skip closing quote */
    return out;
}

}  /* anonymous namespace */

namespace jsonmini {

bool GetString(const std::string& json, const char* key, std::string& out) {
    size_t i = FindKeyValueStart(json, key);
    if (i == std::string::npos) return false;
    while (i < json.size() && std::isspace(static_cast<unsigned char>(json[i]))) i++;
    if (i >= json.size() || json[i] != '"') return false;
    out = DecodeJsonString(json, i);
    return true;
}

bool GetInt64(const std::string& json, const char* key, int64_t& out) {
    size_t i = FindKeyValueStart(json, key);
    if (i == std::string::npos) return false;
    while (i < json.size() && std::isspace(static_cast<unsigned char>(json[i]))) i++;

    size_t start = i;
    if (i < json.size() && (json[i] == '-' || json[i] == '+')) i++;
    while (i < json.size() && std::isdigit(static_cast<unsigned char>(json[i]))) i++;
    if (i == start) return false;

    out = std::strtoll(json.c_str() + start, nullptr, 10);
    return true;
}

}  /* namespace jsonmini */
