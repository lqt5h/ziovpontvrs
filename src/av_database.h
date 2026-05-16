#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace avdb {

struct RawRecord {
    std::string  threatName;
    std::vector<uint8_t> firstBytes;
    std::vector<uint8_t> remainderHash;
    int64_t      remainderLength;
    std::string  fileType;
    int64_t      offsetStart;
    int64_t      offsetEnd;
};

struct ManifestEntry {
    uint8_t  uuid[16];
    uint8_t  status;
    int64_t  updatedAt;
    int64_t  dataOffset;
    uint32_t dataLength;
    std::vector<uint8_t> recordSignature;
};

struct DatabaseFiles {
    std::vector<uint8_t> manifest;
    std::vector<uint8_t> data;
};

enum LoadResult {
    LOAD_OK                  = 0,
    LOAD_FILE_NOT_FOUND      = 1,
    LOAD_MANIFEST_SIG_FAIL   = 2,
    LOAD_CORRUPT             = 3,
};

bool GetDatabaseDir(wchar_t* buf, size_t bufChars);

bool SaveToFile(const std::wstring& dir, const DatabaseFiles& files);
bool SaveBackup(const std::wstring& dir);
bool RestoreBackup(const std::wstring& dir);
bool HasBackup(const std::wstring& dir);
bool CopyDefaultDatabase(const std::wstring& dir);

LoadResult LoadAndVerify(const std::wstring& dir,
                         std::vector<RawRecord>& records,
                         int64_t& generatedAt);

bool DownloadFromServer(const std::string& accessToken, DatabaseFiles& out);
bool DownloadRecordById(const std::string& accessToken,
                        const uint8_t uuid[16],
                        DatabaseFiles& out);

void SetPublicKey(const uint8_t* derData, size_t derLen);

}  // namespace avdb
