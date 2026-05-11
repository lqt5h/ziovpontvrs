#include "av_engine.h"
#include "api_config.h"
#include "http_client.h"
#include "json_mini.h"

#include <windows.h>
#include <wincrypt.h>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>

namespace {

struct DbEntry {
    av::AvRecord record;
    std::string  threatName;
};

CRITICAL_SECTION g_dbLock;
std::map<uint64_t, std::vector<DbEntry>> g_database;
int         g_recordCount  = 0;
std::string g_releaseDate;

uint64_t ReadU64BE(const uint8_t* p) {
    return (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48) |
           (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32) |
           (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16) |
           (uint64_t(p[6]) <<  8) |  uint64_t(p[7]);
}

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char buf[3] = { hex[i], hex[i+1], 0 };
        out.push_back(static_cast<uint8_t>(strtoul(buf, nullptr, 16)));
    }
    return out;
}

std::vector<uint8_t> ComputeSHA256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32, 0);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return hash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    CryptHashData(hHash, data, static_cast<DWORD>(len), 0);
    DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return hash;
}

av::ObjectType MapFileType(const std::string& ft) {
    if (ft == "PE" || ft == "pe" || ft == "exe" || ft == "EXE" ||
        ft == "dll" || ft == "DLL")
        return av::OBJ_PE;
    return av::OBJ_JAVASCRIPT;
}

struct JsonArrayIterator {
    const std::string& json;
    size_t pos;

    explicit JsonArrayIterator(const std::string& j) : json(j), pos(0) {
        pos = json.find('[');
        if (pos != std::string::npos) pos++;
    }

    bool Next(std::string& obj) {
        while (pos < json.size() && (json[pos] == ',' || json[pos] == ' ' ||
               json[pos] == '\n' || json[pos] == '\r' || json[pos] == '\t'))
            pos++;
        if (pos >= json.size() || json[pos] == ']') return false;
        if (json[pos] != '{') return false;

        int depth = 0;
        size_t start = pos;
        bool inStr = false;
        for (; pos < json.size(); pos++) {
            char c = json[pos];
            if (c == '\\' && inStr) { pos++; continue; }
            if (c == '"') { inStr = !inStr; continue; }
            if (inStr) continue;
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) { pos++; break; } }
        }
        obj = json.substr(start, pos - start);
        return true;
    }
};

bool ParseSignatureJson(const std::string& body) {
    EnterCriticalSection(&g_dbLock);
    g_database.clear();
    g_recordCount = 0;

    JsonArrayIterator it(body);
    std::string obj;
    while (it.Next(obj)) {
        std::string status;
        jsonmini::GetString(obj, "status", status);
        if (status == "DELETED") continue;

        std::string firstBytesHex, remainderHashHex, fileType, threatName;
        int64_t remainderLength = 0, offsetStart = 0, offsetEnd = 0;
        std::string digitalSig;

        if (!jsonmini::GetString(obj, "firstBytesHex", firstBytesHex)) continue;
        if (!jsonmini::GetString(obj, "remainderHashHex", remainderHashHex)) continue;
        if (!jsonmini::GetInt64(obj, "remainderLength", remainderLength)) continue;
        if (!jsonmini::GetString(obj, "fileType", fileType)) continue;
        jsonmini::GetInt64(obj, "offsetStart", offsetStart);
        jsonmini::GetInt64(obj, "offsetEnd", offsetEnd);
        jsonmini::GetString(obj, "threatName", threatName);
        jsonmini::GetString(obj, "digitalSignatureBase64", digitalSig);

        auto prefixBytes = HexToBytes(firstBytesHex);
        if (prefixBytes.size() < 8) {
            prefixBytes.resize(8, 0);
        }

        uint64_t prefix = ReadU64BE(prefixBytes.data());

        DbEntry entry;
        entry.threatName = threatName;
        entry.record.signaturePrefix  = prefix;
        entry.record.signatureLength  = static_cast<uint32_t>(8 + remainderLength);
        entry.record.signatureHash    = HexToBytes(remainderHashHex);
        entry.record.offsetBegin      = static_cast<uint64_t>(offsetStart);
        entry.record.offsetEnd        = static_cast<uint64_t>(offsetEnd);
        entry.record.objectType       = MapFileType(fileType);

        if (!digitalSig.empty()) {
            DWORD decLen = 0;
            CryptStringToBinaryA(digitalSig.c_str(), static_cast<DWORD>(digitalSig.size()),
                                 CRYPT_STRING_BASE64, nullptr, &decLen, nullptr, nullptr);
            entry.record.recordSignature.resize(decLen);
            CryptStringToBinaryA(digitalSig.c_str(), static_cast<DWORD>(digitalSig.size()),
                                 CRYPT_STRING_BASE64, entry.record.recordSignature.data(),
                                 &decLen, nullptr, nullptr);
        }

        g_database[prefix].push_back(std::move(entry));
        g_recordCount++;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    char dateBuf[32];
    snprintf(dateBuf, sizeof(dateBuf), "%02u.%02u.%04u %02u:%02u",
             st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
    g_releaseDate = dateBuf;

    LeaveCriticalSection(&g_dbLock);
    return g_recordCount > 0 || body.find("[]") != std::string::npos;
}

}  // anonymous namespace

namespace av {

void InitDatabase() {
    InitializeCriticalSection(&g_dbLock);
}

void ShutdownDatabase() {
    EnterCriticalSection(&g_dbLock);
    g_database.clear();
    g_recordCount = 0;
    LeaveCriticalSection(&g_dbLock);
    DeleteCriticalSection(&g_dbLock);
}

bool LoadDatabase(const std::string& accessToken) {
    http::Response resp;
    if (!http::Get(API_PATH_SIGNATURES, &accessToken, resp))
        return false;
    if (resp.status_code != 200)
        return false;
    return ParseSignatureJson(resp.body);
}

int GetRecordCount() {
    EnterCriticalSection(&g_dbLock);
    int n = g_recordCount;
    LeaveCriticalSection(&g_dbLock);
    return n;
}

std::string GetReleaseDate() {
    EnterCriticalSection(&g_dbLock);
    std::string d = g_releaseDate;
    LeaveCriticalSection(&g_dbLock);
    return d;
}

ObjectType DetectFileTypeFromHeader(const uint8_t* data, size_t len) {
    if (len >= 2 && data[0] == 'M' && data[1] == 'Z')
        return OBJ_PE;
    return OBJ_JAVASCRIPT;
}

ObjectType DetectFileType(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return OBJ_PE;
    uint8_t header[4] = {};
    DWORD read = 0;
    ReadFile(hFile, header, 4, &read, nullptr);
    CloseHandle(hFile);
    return DetectFileTypeFromHeader(header, read);
}

ScanResult ScanStream(const uint8_t* data, size_t dataLen, ObjectType objType) {
    if (dataLen < 8) return SCAN_CLEAN;

    EnterCriticalSection(&g_dbLock);

    for (size_t pos = 0; pos + 8 <= dataLen; pos++) {
        uint64_t prefix = ReadU64BE(data + pos);

        auto it = g_database.find(prefix);
        if (it == g_database.end())
            continue;

        for (const auto& entry : it->second) {
            const AvRecord& rec = entry.record;

            if (rec.objectType != objType)
                continue;

            if (pos < rec.offsetBegin || pos > rec.offsetEnd)
                continue;

            uint32_t extra = rec.signatureLength - 8;
            if (pos + 8 + extra > dataLen)
                continue;

            std::vector<uint8_t> fullSig(rec.signatureLength);
            memcpy(fullSig.data(), data + pos, 8);
            if (extra > 0)
                memcpy(fullSig.data() + 8, data + pos + 8, extra);

            auto hash = ComputeSHA256(fullSig.data(), fullSig.size());

            if (hash == rec.signatureHash) {
                LeaveCriticalSection(&g_dbLock);
                return SCAN_MALICIOUS;
            }
        }
    }

    LeaveCriticalSection(&g_dbLock);
    return SCAN_CLEAN;
}

ScanReport ScanFile(const std::wstring& path) {
    ScanReport report;
    report.filePath = path;
    report.result = SCAN_ERROR;

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return report;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        report.result = SCAN_CLEAN;
        return report;
    }

    if (fileSize.QuadPart > 256 * 1024 * 1024) {
        CloseHandle(hFile);
        report.result = SCAN_CLEAN;
        return report;
    }

    std::vector<uint8_t> buf(static_cast<size_t>(fileSize.QuadPart));
    DWORD read = 0;
    if (!ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr)) {
        CloseHandle(hFile);
        return report;
    }
    CloseHandle(hFile);

    ObjectType objType = DetectFileTypeFromHeader(buf.data(), read);
    report.result = ScanStream(buf.data(), read, objType);
    return report;
}

std::vector<ScanReport> ScanDirectory(const std::wstring& dirPath) {
    std::vector<ScanReport> reports;
    std::wstring searchPath = dirPath;
    if (!searchPath.empty() && searchPath.back() != L'\\')
        searchPath += L'\\';
    searchPath += L"*";

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return reports;

    std::wstring base = dirPath;
    if (!base.empty() && base.back() != L'\\')
        base += L'\\';

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;
            auto sub = ScanDirectory(base + fd.cFileName);
            reports.insert(reports.end(), sub.begin(), sub.end());
        } else {
            auto r = ScanFile(base + fd.cFileName);
            reports.push_back(std::move(r));
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return reports;
}

}  // namespace av
