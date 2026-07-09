#ifndef BE_UTIL_H
#define BE_UTIL_H

/********************************************************************
*
*   util.h
*
*   Utility Functions
*
********************************************************************/

#include "config.h"
#include "types.h"
#include "ecc.h"

#include <chrono>
#include <vector>
#include <string>

namespace BE
{

/*==============================================================
    Hex Conversion
==============================================================*/

std::string BytesToHex(
        const unsigned char* data,
        size_t length);

std::vector<unsigned char>
HexToBytes(
        const std::string& hex);

std::string BNToHex(
        const BIGNUM* bn);

BIGNUM*
HexToBN(
        const std::string& hex);

/*==============================================================
    String Utility
==============================================================*/

std::vector<std::string>
Split(
        const std::string& text,
        char delimiter);

std::string
Trim(
        const std::string& text);

std::string
ToUpper(
        const std::string& text);

std::string
ToLower(
        const std::string& text);

/*==============================================================
    File Utility
==============================================================*/

bool
SaveText(
        const std::string& filename,
        const std::string& content);

bool
LoadText(
        const std::string& filename,
        std::string& content);

bool
SaveBinary(
        const std::string& filename,
        const std::vector<unsigned char>& data);

bool
LoadBinary(
        const std::string& filename,
        std::vector<unsigned char>& data);

/*==============================================================
    ECC Serialization
==============================================================*/

bool
SavePoint(
        const ECCContext& ecc,
        const EC_POINT* point,
        const std::string& filename);

ECPoint_ptr
LoadPoint(
        const ECCContext& ecc,
        const std::string& filename);

bool
SaveScalar(
        const BIGNUM* scalar,
        const std::string& filename);

BN_ptr
LoadScalar(
        const std::string& filename);

/*==============================================================
    Random Utility
==============================================================*/

std::string
RandomString(
        size_t length);

uint64_t
RandomUInt64();

std::vector<unsigned char>
RandomBytes(
        size_t length);

std::string
RandomHex(
        size_t byteLength);

bool
RandomBool();

int
RandomInt(
        int minValue,
        int maxValue);

/*==============================================================
    Timer
==============================================================*/

class Timer
{
public:

    Timer();

    void Start();

    void Stop();

    void Restart();

    double Seconds() const;

    double Milliseconds() const;

    double Microseconds() const;

    double Nanoseconds() const;

private:

    std::chrono::high_resolution_clock::time_point start_;

    std::chrono::high_resolution_clock::time_point end_;
};

/*==============================================================
    Console Output
==============================================================*/

void
PrintTitle(
        const std::string& title);

void
PrintSeparator();

void
PrintMessage(
        const std::string& message);

void
PrintScalar(
        const BIGNUM* scalar);

void
PrintPoint(
        const ECCContext& ecc,
        const EC_POINT* point);

void
PrintBytes(
        const std::vector<unsigned char>& bytes);

void
PrintStringVector(
        const std::vector<std::string>& vec);

/*==============================================================
    Header Information
==============================================================*/

struct HeaderInfo
{
    std::string policy;

    size_t rows;

    size_t cols;

    size_t userCount;

    size_t groupCount;
};

void
PrintHeaderInfo(
        const HeaderInfo& header);

/*==============================================================
    Utility
==============================================================*/

bool
FileExists(
        const std::string& filename);

std::string
CurrentTime();

/*==============================================================
    Debug
==============================================================*/

void
PrintBanner();

void
PrintSuccess(
        const std::string& message);

void
PrintError(
        const std::string& message);

void
CheckOpenSSLError();

void
Assert(
        bool condition,
        const std::string& message);

/*==============================================================
    Misc
==============================================================*/

bool
IsZero(
        const BIGNUM* bn);

bool
IsOne(
        const BIGNUM* bn);

bool
CompareBN(
        const BIGNUM* a,
        const BIGNUM* b);

BN_ptr
CopyScalar(
        const BIGNUM* bn);

ECPoint_ptr
CopyPoint(
        const ECCContext& ecc,
        const EC_POINT* point);

} // namespace BE

#endif