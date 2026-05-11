#include "av_database.h"
#include "api_config.h"
#include "http_client.h"

#include <windows.h>
#include <wincrypt.h>
#include <cstring>
#include <string>
#include <vector>

namespace {

static const char MANIFEST_MAGIC[] = "MF-Mareychenko";
static const char DATA_MAGIC[]     = "DB-Mareychenko";
static const int  MAGIC_LEN        = 14;
static const int  MF_HEADER_SIZE   = 69;
static const int  DATA_HEADER_SIZE = 20;

static HCRYPTKEY g_hPubKey = 0;
static HCRYPTPROV g_hProv  = 0;

uint16_t ReadU16BE(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | p[1];
}

uint32_t ReadU32BE(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  |  p[3];
}

int64_t ReadI64BE(const uint8_t* p) {
    uint64_t v = (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48) |
                 (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32) |
                 (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16) |
                 (uint64_t(p[6]) <<  8) |  uint64_t(p[7]);
    return static_cast<int64_t>(v);
}

std::vector<uint8_t> ComputeSHA256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32, 0);
    HCRYPTPROV hP = 0;
    HCRYPTHASH hH = 0;
    if (!CryptAcquireContextW(&hP, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return hash;
    if (!CryptCreateHash(hP, CALG_SHA_256, 0, 0, &hH)) {
        CryptReleaseContext(hP, 0);
        return hash;
    }
    CryptHashData(hH, data, (DWORD)len, 0);
    DWORD hl = 32;
    CryptGetHashParam(hH, HP_HASHVAL, hash.data(), &hl, 0);
    CryptDestroyHash(hH);
    CryptReleaseContext(hP, 0);
    return hash;
}

bool VerifyRSASHA256(const uint8_t* data, size_t dataLen,
                     const uint8_t* sig,  size_t sigLen) {
    if (!g_hPubKey || !g_hProv) return false;

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(g_hProv, CALG_SHA_256, 0, 0, &hHash))
        return false;
    if (!CryptHashData(hHash, data, (DWORD)dataLen, 0)) {
        CryptDestroyHash(hHash);
        return false;
    }

    std::vector<uint8_t> reversed(sig, sig + sigLen);
    for (size_t i = 0; i < reversed.size() / 2; i++)
        std::swap(reversed[i], reversed[reversed.size() - 1 - i]);

    BOOL ok = CryptVerifySignature(hHash, reversed.data(), (DWORD)reversed.size(),
                                   g_hPubKey, nullptr, 0);
    CryptDestroyHash(hHash);
    return ok != FALSE;
}

bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }
    out.resize((size_t)sz.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(hFile, out.data(), (DWORD)out.size(), &read, nullptr);
    CloseHandle(hFile);
    return ok && read == out.size();
}

bool WriteFileBytes(const std::wstring& path, const std::vector<uint8_t>& data) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, data.data(), (DWORD)data.size(), &written, nullptr);
    CloseHandle(hFile);
    return ok && written == data.size();
}

bool CopyFileSimple(const std::wstring& src, const std::wstring& dst) {
    return CopyFileW(src.c_str(), dst.c_str(), FALSE) != FALSE;
}

bool ParseManifest(const std::vector<uint8_t>& mf,
                   int64_t& generatedAt,
                   uint32_t& recordCount,
                   uint8_t dataSha256[32],
                   std::vector<avdb::ManifestEntry>& entries,
                   size_t& unsignedLen) {
    if (mf.size() < (size_t)MF_HEADER_SIZE + 4) return false;
    if (memcmp(mf.data(), MANIFEST_MAGIC, MAGIC_LEN) != 0) return false;

    const uint8_t* p = mf.data();
    generatedAt = ReadI64BE(p + 17);
    recordCount = ReadU32BE(p + 33);
    memcpy(dataSha256, p + 37, 32);

    size_t pos = MF_HEADER_SIZE;
    entries.clear();
    entries.reserve(recordCount);
    for (uint32_t i = 0; i < recordCount; i++) {
        if (pos + 37 > mf.size()) return false;
        avdb::ManifestEntry e;
        memcpy(e.uuid, &mf[pos], 16); pos += 16;
        e.status     = mf[pos]; pos += 1;
        e.updatedAt  = ReadI64BE(&mf[pos]); pos += 8;
        e.dataOffset = ReadI64BE(&mf[pos]); pos += 8;
        e.dataLength = ReadU32BE(&mf[pos]); pos += 4;
        uint32_t sigLen = ReadU32BE(&mf[pos]); pos += 4;
        if (pos + sigLen > mf.size()) return false;
        e.recordSignature.assign(mf.begin() + pos, mf.begin() + pos + sigLen);
        pos += sigLen;
        entries.push_back(std::move(e));
    }
    unsignedLen = pos;
    return true;
}

bool VerifyManifestSignature(const std::vector<uint8_t>& mf, size_t unsignedLen) {
    if (unsignedLen + 4 > mf.size()) return false;
    uint32_t sigLen = ReadU32BE(&mf[unsignedLen]);
    if (unsignedLen + 4 + sigLen > mf.size()) return false;
    return VerifyRSASHA256(mf.data(), unsignedLen,
                           &mf[unsignedLen + 4], sigLen);
}

bool ParseDataRecords(const std::vector<uint8_t>& data,
                      const std::vector<avdb::ManifestEntry>& entries,
                      std::vector<avdb::RawRecord>& records) {
    if (data.size() < (size_t)DATA_HEADER_SIZE) return false;
    if (memcmp(data.data(), DATA_MAGIC, MAGIC_LEN) != 0) return false;

    uint32_t recCount = ReadU32BE(data.data() + 16);
    const uint8_t* base = data.data() + DATA_HEADER_SIZE;
    size_t baseLen = data.size() - DATA_HEADER_SIZE;

    records.clear();
    records.reserve(entries.size());

    for (const auto& e : entries) {
        if (e.status != 0) continue;

        if (e.dataOffset < 0 || (size_t)e.dataOffset + e.dataLength > baseLen)
            continue;

        const uint8_t* rp = base + e.dataOffset;
        const uint8_t* rEnd = rp + e.dataLength;

        auto readU32 = [&](uint32_t& v) -> bool {
            if (rp + 4 > rEnd) return false;
            v = ReadU32BE(rp); rp += 4;
            return true;
        };
        auto readBytes = [&](uint32_t len, std::vector<uint8_t>& out) -> bool {
            if (rp + len > rEnd) return false;
            out.assign(rp, rp + len);
            rp += len;
            return true;
        };
        auto readStr = [&](std::string& s) -> bool {
            uint32_t len;
            if (!readU32(len)) return false;
            if (rp + len > rEnd) return false;
            s.assign(reinterpret_cast<const char*>(rp), len);
            rp += len;
            return true;
        };
        auto readI64 = [&](int64_t& v) -> bool {
            if (rp + 8 > rEnd) return false;
            v = ReadI64BE(rp); rp += 8;
            return true;
        };
        auto readLenBytes = [&](std::vector<uint8_t>& out) -> bool {
            uint32_t len;
            if (!readU32(len)) return false;
            return readBytes(len, out);
        };

        avdb::RawRecord rec;
        if (!readStr(rec.threatName)) continue;
        if (!readLenBytes(rec.firstBytes)) continue;
        if (!readLenBytes(rec.remainderHash)) continue;
        if (!readI64(rec.remainderLength)) continue;
        if (!readStr(rec.fileType)) continue;
        if (!readI64(rec.offsetStart)) continue;
        if (!readI64(rec.offsetEnd)) continue;

        if (!e.recordSignature.empty()) {
            bool sigOk = VerifyRSASHA256(base + e.dataOffset, e.dataLength,
                                         e.recordSignature.data(),
                                         e.recordSignature.size());
            if (!sigOk) continue;
        }

        records.push_back(std::move(rec));
    }
    return true;
}

std::wstring GetExeDir() {
    WCHAR path[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    WCHAR* slash = wcsrchr(path, L'\\');
    if (slash) *(slash + 1) = L'\0';
    return path;
}

std::string UuidToHex(const uint8_t uuid[16]) {
    char buf[64];
    snprintf(buf, sizeof(buf),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);
    return buf;
}

std::string ToUtf8(const wchar_t* ws) {
    if (!ws || !*ws) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, s.data(), n, nullptr, nullptr);
    return s;
}

bool ParseMultipartResponse(const std::string& body, const std::string& boundary,
                            std::vector<uint8_t>& manifest, std::vector<uint8_t>& data) {
    manifest.clear();
    data.clear();
    std::string delim = "--" + boundary;
    size_t pos = 0;
    int partIdx = 0;
    while ((pos = body.find(delim, pos)) != std::string::npos) {
        pos += delim.size();
        if (pos >= body.size()) break;
        if (body[pos] == '-' && pos + 1 < body.size() && body[pos+1] == '-') break;

        size_t headerEnd = body.find("\r\n\r\n", pos);
        if (headerEnd == std::string::npos) break;
        size_t contentStart = headerEnd + 4;

        size_t nextDelim = body.find(delim, contentStart);
        if (nextDelim == std::string::npos) break;
        size_t contentEnd = nextDelim;
        if (contentEnd >= 2 && body[contentEnd-2] == '\r' && body[contentEnd-1] == '\n')
            contentEnd -= 2;

        auto* bStart = reinterpret_cast<const uint8_t*>(body.data() + contentStart);
        size_t bLen = contentEnd - contentStart;

        if (partIdx == 0)
            manifest.assign(bStart, bStart + bLen);
        else if (partIdx == 1)
            data.assign(bStart, bStart + bLen);
        partIdx++;
    }
    return !manifest.empty() && !data.empty();
}

std::string ExtractBoundary(const std::string& contentType) {
    auto pos = contentType.find("boundary=");
    if (pos == std::string::npos) return "";
    auto start = pos + 9;
    auto end = contentType.find_first_of(";\r\n ", start);
    if (end == std::string::npos) end = contentType.size();
    std::string b = contentType.substr(start, end - start);
    if (b.size() >= 2 && b.front() == '"' && b.back() == '"')
        b = b.substr(1, b.size() - 2);
    return b;
}

}  // anonymous namespace

namespace avdb {

bool GetDatabaseDir(wchar_t* buf, size_t bufChars) {
    DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)bufChars);
    if (n == 0 || n >= bufChars) return false;
    wchar_t* slash = wcsrchr(buf, L'\\');
    if (slash) *(slash + 1) = L'\0';
    return true;
}

void SetPublicKey(const uint8_t* derData, size_t derLen) {
    if (g_hPubKey) { CryptDestroyKey(g_hPubKey); g_hPubKey = 0; }
    if (g_hProv)   { CryptReleaseContext(g_hProv, 0); g_hProv = 0; }

    if (!CryptAcquireContextW(&g_hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return;

    CERT_PUBLIC_KEY_INFO* pubInfo = nullptr;
    DWORD pubInfoLen = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                             derData, (DWORD)derLen,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr,
                             &pubInfo, &pubInfoLen)) {
        CryptReleaseContext(g_hProv, 0);
        g_hProv = 0;
        return;
    }

    CryptImportPublicKeyInfo(g_hProv, X509_ASN_ENCODING, pubInfo, &g_hPubKey);
    LocalFree(pubInfo);
}

bool SaveToFile(const std::wstring& dir, const DatabaseFiles& files) {
    std::wstring mfPath   = dir + L"manifest.bin";
    std::wstring dataPath = dir + L"data.bin";
    if (!WriteFileBytes(mfPath, files.manifest)) return false;
    if (!WriteFileBytes(dataPath, files.data))   return false;
    return true;
}

bool SaveBackup(const std::wstring& dir) {
    std::wstring mfSrc   = dir + L"manifest.bin";
    std::wstring dataSrc = dir + L"data.bin";
    std::wstring mfDst   = dir + L"manifest.bin.bak";
    std::wstring dataDst = dir + L"data.bin.bak";

    if (GetFileAttributesW(mfSrc.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;

    CopyFileSimple(mfSrc, mfDst);
    CopyFileSimple(dataSrc, dataDst);
    return true;
}

bool RestoreBackup(const std::wstring& dir) {
    std::wstring mfBak   = dir + L"manifest.bin.bak";
    std::wstring dataBak = dir + L"data.bin.bak";
    std::wstring mfDst   = dir + L"manifest.bin";
    std::wstring dataDst = dir + L"data.bin";

    if (GetFileAttributesW(mfBak.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;

    CopyFileSimple(mfBak, mfDst);
    CopyFileSimple(dataBak, dataDst);
    return true;
}

bool HasBackup(const std::wstring& dir) {
    std::wstring mfBak = dir + L"manifest.bin.bak";
    return GetFileAttributesW(mfBak.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool CopyDefaultDatabase(const std::wstring& dir) {
    std::wstring exeDir = GetExeDir();
    std::wstring defMf   = exeDir + L"default_manifest.bin";
    std::wstring defData = exeDir + L"default_data.bin";

    if (GetFileAttributesW(defMf.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;

    CopyFileSimple(defMf, dir + L"manifest.bin");
    CopyFileSimple(defData, dir + L"data.bin");
    return true;
}

LoadResult LoadAndVerify(const std::wstring& dir,
                         std::vector<RawRecord>& records,
                         int64_t& generatedAt) {
    std::wstring mfPath   = dir + L"manifest.bin";
    std::wstring dataPath = dir + L"data.bin";

    std::vector<uint8_t> mfBytes, dataBytes;
    if (!ReadFileBytes(mfPath, mfBytes) || !ReadFileBytes(dataPath, dataBytes))
        return LOAD_FILE_NOT_FOUND;

    uint32_t recordCount = 0;
    uint8_t dataSha256[32];
    std::vector<ManifestEntry> entries;
    size_t unsignedLen = 0;

    if (!ParseManifest(mfBytes, generatedAt, recordCount, dataSha256, entries, unsignedLen))
        return LOAD_CORRUPT;

    auto actualHash = ComputeSHA256(dataBytes.data(), dataBytes.size());
    if (memcmp(actualHash.data(), dataSha256, 32) != 0)
        return LOAD_CORRUPT;

    if (g_hPubKey) {
        if (!VerifyManifestSignature(mfBytes, unsignedLen))
            return LOAD_MANIFEST_SIG_FAIL;
    }

    if (!ParseDataRecords(dataBytes, entries, records))
        return LOAD_CORRUPT;

    return LOAD_OK;
}

bool DownloadFromServer(const std::string& accessToken, DatabaseFiles& out) {
    http::Response resp;
    if (!http::Get(API_PATH_BINARY_SIGNATURES_FULL, &accessToken, resp))
        return false;
    if (resp.status_code != 200)
        return false;

    std::string contentType;
    size_t ctPos = resp.body.find("Content-Type:");
    if (resp.body.size() < 4) return false;

    out.manifest.clear();
    out.data.clear();

    const uint8_t* raw = reinterpret_cast<const uint8_t*>(resp.body.data());
    size_t rawLen = resp.body.size();

    if (rawLen >= MAGIC_LEN && memcmp(raw, MANIFEST_MAGIC, MAGIC_LEN) == 0) {
        out.manifest.assign(raw, raw + rawLen);
        return false;
    }

    if (rawLen > 2 && raw[0] == '-' && raw[1] == '-') {
        size_t lineEnd = resp.body.find("\r\n");
        if (lineEnd == std::string::npos) return false;
        std::string boundary = resp.body.substr(2, lineEnd - 2);
        return ParseMultipartResponse(resp.body, boundary, out.manifest, out.data);
    }

    return false;
}

bool DownloadRecordById(const std::string& accessToken,
                        const uint8_t uuid[16],
                        DatabaseFiles& out) {
    std::string id = UuidToHex(uuid);
    std::string body = "{\"ids\":[\"" + id + "\"]}";

    http::Response resp;
    if (!http::Post(API_PATH_BINARY_SIGNATURES_BY_IDS, body, &accessToken, resp))
        return false;
    if (resp.status_code != 200)
        return false;

    if (resp.body.size() > 2 &&
        resp.body[0] == '-' && resp.body[1] == '-') {
        size_t lineEnd = resp.body.find("\r\n");
        if (lineEnd == std::string::npos) return false;
        std::string boundary = resp.body.substr(2, lineEnd - 2);
        return ParseMultipartResponse(resp.body, boundary, out.manifest, out.data);
    }
    return false;
}

}  // namespace avdb
