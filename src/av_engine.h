#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace av {

enum ObjectType : uint8_t {
    OBJ_PE          = 0,
    OBJ_JAVASCRIPT  = 1,
};

struct AvRecord {
    uint64_t    signaturePrefix;
    uint32_t    signatureLength;
    std::vector<uint8_t> signatureHash;
    uint64_t    offsetBegin;
    uint64_t    offsetEnd;
    ObjectType  objectType;
    std::vector<uint8_t> recordSignature;
};

enum ScanResult {
    SCAN_CLEAN     = 0,
    SCAN_MALICIOUS = 1,
    SCAN_ERROR     = 2,
};

struct ScanReport {
    ScanResult result;
    std::wstring filePath;
    std::string  threatName;
};

ObjectType DetectFileType(const std::wstring& path);
ObjectType DetectFileTypeFromHeader(const uint8_t* data, size_t len);

void InitDatabase();
void ShutdownDatabase();
bool LoadDatabase(const std::string& accessToken);
bool LoadDatabaseFromDisk();
bool UpdateDatabase(const std::string& accessToken);

int         GetRecordCount();
std::string GetReleaseDate();

ScanResult  ScanStream(const uint8_t* data, size_t dataLen, ObjectType objType);
ScanReport  ScanFile(const std::wstring& path);
std::vector<ScanReport> ScanDirectory(const std::wstring& dirPath);

}  // namespace av
