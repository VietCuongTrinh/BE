/********************************************************************
*
*   util.cpp
*
*   Utility Functions
*
********************************************************************/

#include "util.h"

#include <openssl/rand.h>
#include <openssl/err.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace BE
{

/*==============================================================
    Bytes -> Hex
==============================================================*/

std::string BytesToHex(
        const unsigned char* data,
        size_t length)
{
    if(data == nullptr || length == 0)
        return "";

    std::ostringstream oss;

    oss << std::uppercase
        << std::hex
        << std::setfill('0');

    for(size_t i = 0; i < length; ++i)
    {
        oss << std::setw(2)
            << static_cast<unsigned int>(data[i]);
    }

    return oss.str();
}

/*-------------------------------------------------------------*/

std::vector<unsigned char>
HexToBytes(
        const std::string& hex)
{
    std::vector<unsigned char> result;

    if(hex.empty())
        return result;

    if(hex.length() % 2 != 0)
        return result;

    result.reserve(hex.length() / 2);

    for(size_t i = 0; i < hex.length(); i += 2)
    {
        unsigned int value;

        std::stringstream ss;

        ss << std::hex
           << hex.substr(i,2);

        ss >> value;

        result.push_back(
            static_cast<unsigned char>(value));
    }

    return result;
}

/*==============================================================
    BIGNUM <-> Hex
==============================================================*/

std::string BNToHex(
        const BIGNUM* bn)
{
    if(bn == nullptr)
        return "";

    char* hex =
        BN_bn2hex(bn);

    if(hex == nullptr)
        return "";

    std::string result(hex);

    OPENSSL_free(hex);

    return result;
}

/*-------------------------------------------------------------*/

BIGNUM*
HexToBN(
        const std::string& hex)
{
    if(hex.empty())
        return nullptr;

    BIGNUM* bn = nullptr;

    if(BN_hex2bn(
            &bn,
            hex.c_str()) == 0)
    {
        return nullptr;
    }

    return bn;
}

/*==============================================================
    Byte Vector <-> Hex
==============================================================*/

std::string BytesToHex(
        const std::vector<unsigned char>& data)
{
    if(data.empty())
        return "";

    return BytesToHex(
            data.data(),
            data.size());
}

/*-------------------------------------------------------------*/

bool IsHexString(
        const std::string& str)
{
    if(str.empty())
        return false;

    for(char c : str)
    {
        if(!std::isxdigit(
                static_cast<unsigned char>(c)))
        {
            return false;
        }
    }

    return true;
}

/*-------------------------------------------------------------*/

std::string NormalizeHex(
        const std::string& hex)
{
    std::string result;

    result.reserve(hex.length());

    for(char c : hex)
    {
        if(std::isxdigit(
                static_cast<unsigned char>(c)))
        {
            result.push_back(
                static_cast<char>(
                    std::toupper(
                        static_cast<unsigned char>(c))));
        }
    }

    return result;
}

} // namespace BE
/*==============================================================
    String Utility
==============================================================*/

/*-------------------------------------------------------------
    Trim
--------------------------------------------------------------*/

std::string Trim(
        const std::string& text)
{
    if(text.empty())
        return "";

    size_t first = 0;

    while(first < text.length() &&
          std::isspace(
            static_cast<unsigned char>(text[first])))
    {
        ++first;
    }

    if(first == text.length())
        return "";

    size_t last = text.length() - 1;

    while(last > first &&
          std::isspace(
            static_cast<unsigned char>(text[last])))
    {
        --last;
    }

    return text.substr(
            first,
            last - first + 1);
}

/*-------------------------------------------------------------
    Split
--------------------------------------------------------------*/

std::vector<std::string>
Split(
        const std::string& text,
        char delimiter)
{
    std::vector<std::string> result;

    std::stringstream ss(text);

    std::string token;

    while(std::getline(
            ss,
            token,
            delimiter))
    {
        token = Trim(token);

        if(!token.empty())
        {
            result.push_back(token);
        }
    }

    return result;
}

/*-------------------------------------------------------------
    ToUpper
--------------------------------------------------------------*/

std::string
ToUpper(
        const std::string& text)
{
    std::string result(text);

    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                std::toupper(c));
        });

    return result;
}

/*-------------------------------------------------------------
    ToLower
--------------------------------------------------------------*/

std::string
ToLower(
        const std::string& text)
{
    std::string result(text);

    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                std::tolower(c));
        });

    return result;
}

/*-------------------------------------------------------------
    StartsWith
--------------------------------------------------------------*/

bool StartsWith(
        const std::string& text,
        const std::string& prefix)
{
    if(prefix.size() > text.size())
        return false;

    return std::equal(
            prefix.begin(),
            prefix.end(),
            text.begin());
}

/*-------------------------------------------------------------
    EndsWith
--------------------------------------------------------------*/

bool EndsWith(
        const std::string& text,
        const std::string& suffix)
{
    if(suffix.size() > text.size())
        return false;

    return std::equal(
            suffix.rbegin(),
            suffix.rend(),
            text.rbegin());
}

/*-------------------------------------------------------------
    ReplaceAll
--------------------------------------------------------------*/

std::string
ReplaceAll(
        std::string text,
        const std::string& from,
        const std::string& to)
{
    if(from.empty())
        return text;

    size_t pos = 0;

    while((pos = text.find(from, pos))
            != std::string::npos)
    {
        text.replace(
                pos,
                from.length(),
                to);

        pos += to.length();
    }

    return text;
}

/*-------------------------------------------------------------
    Join
--------------------------------------------------------------*/

std::string
Join(
        const std::vector<std::string>& list,
        const std::string& delimiter)
{
    if(list.empty())
        return "";

    std::ostringstream oss;

    for(size_t i = 0; i < list.size(); ++i)
    {
        oss << list[i];

        if(i + 1 != list.size())
            oss << delimiter;
    }

    return oss.str();
}
/*==============================================================
    File Utility
==============================================================*/

/*-------------------------------------------------------------
    SaveText
--------------------------------------------------------------*/

bool SaveText(
        const std::string& filename,
        const std::string& content)
{
    std::ofstream ofs(
        filename,
        std::ios::out | std::ios::trunc);

    if(!ofs.is_open())
        return false;

    ofs << content;

    ofs.close();

    return ofs.good();
}

/*-------------------------------------------------------------*/

bool LoadText(
        const std::string& filename,
        std::string& content)
{
    std::ifstream ifs(
        filename,
        std::ios::in);

    if(!ifs.is_open())
        return false;

    std::stringstream buffer;

    buffer << ifs.rdbuf();

    content = buffer.str();

    ifs.close();

    return true;
}

/*-------------------------------------------------------------
    SaveBinary
--------------------------------------------------------------*/

bool SaveBinary(
        const std::string& filename,
        const std::vector<unsigned char>& data)
{
    std::ofstream ofs(
        filename,
        std::ios::binary | std::ios::out);

    if(!ofs.is_open())
        return false;

    if(!data.empty())
    {
        ofs.write(
            reinterpret_cast<const char*>(
                data.data()),
            static_cast<std::streamsize>(
                data.size()));
    }

    ofs.close();

    return ofs.good();
}

/*-------------------------------------------------------------*/

bool LoadBinary(
        const std::string& filename,
        std::vector<unsigned char>& data)
{
    std::ifstream ifs(
        filename,
        std::ios::binary | std::ios::ate);

    if(!ifs.is_open())
        return false;

    std::streamsize size =
        ifs.tellg();

    if(size < 0)
    {
        ifs.close();
        return false;
    }

    ifs.seekg(
        0,
        std::ios::beg);

    data.resize(
        static_cast<size_t>(size));

    if(size > 0)
    {
        if(!ifs.read(
                reinterpret_cast<char*>(
                    data.data()),
                size))
        {
            ifs.close();
            return false;
        }
    }

    ifs.close();

    return true;
}

/*-------------------------------------------------------------
    CreateDirectory
--------------------------------------------------------------*/

bool CreateDirectory(
        const std::string& directory)
{
    namespace fs = std::filesystem;

    try
    {
        if(fs::exists(directory))
            return true;

        return fs::create_directories(directory);
    }
    catch(...)
    {
        return false;
    }
}

/*-------------------------------------------------------------
    DeleteFile
--------------------------------------------------------------*/

bool DeleteFile(
        const std::string& filename)
{
    namespace fs = std::filesystem;

    try
    {
        if(!fs::exists(filename))
            return false;

        return fs::remove(filename);
    }
    catch(...)
    {
        return false;
    }
}

/*-------------------------------------------------------------
    FileSize
--------------------------------------------------------------*/

std::uintmax_t FileSize(
        const std::string& filename)
{
    namespace fs = std::filesystem;

    try
    {
        if(!fs::exists(filename))
            return 0;

        return fs::file_size(filename);
    }
    catch(...)
    {
        return 0;
    }
}

/*-------------------------------------------------------------
    ReadLines
--------------------------------------------------------------*/

std::vector<std::string>
ReadLines(
        const std::string& filename)
{
    std::vector<std::string> lines;

    std::ifstream ifs(filename);

    if(!ifs.is_open())
        return lines;

    std::string line;

    while(std::getline(ifs,line))
    {
        lines.push_back(line);
    }

    return lines;
}

/*-------------------------------------------------------------
    WriteLines
--------------------------------------------------------------*/

bool WriteLines(
        const std::string& filename,
        const std::vector<std::string>& lines)
{
    std::ofstream ofs(filename);

    if(!ofs.is_open())
        return false;

    for(const auto& line : lines)
    {
        ofs << line << '\n';
    }

    return true;
}
/*==============================================================
    ECC Serialization
==============================================================*/

/*-------------------------------------------------------------
    SavePoint
--------------------------------------------------------------*/

bool SavePoint(
        const ECCContext& ecc,
        const EC_POINT* point,
        const std::string& filename)
{
    if(point == nullptr)
        return false;

    std::string hex =
        PointToHex(
            ecc,
            point,
            POINT_CONVERSION_COMPRESSED);

    return SaveText(
            filename,
            hex);
}

/*-------------------------------------------------------------*/

ECPoint_ptr
LoadPoint(
        const ECCContext& ecc,
        const std::string& filename)
{
    std::string hex;

    if(!LoadText(
            filename,
            hex))
    {
        return ECPoint_ptr(
            nullptr,
            EC_POINT_free);
    }

    hex = Trim(hex);

    return HexToPoint(
            ecc,
            hex);
}

/*-------------------------------------------------------------
    SaveScalar
--------------------------------------------------------------*/

bool SaveScalar(
        const BIGNUM* scalar,
        const std::string& filename)
{
    if(scalar == nullptr)
        return false;

    return SaveText(
            filename,
            ScalarToHex(scalar));
}

/*-------------------------------------------------------------*/

BN_ptr
LoadScalar(
        const std::string& filename)
{
    std::string hex;

    if(!LoadText(
            filename,
            hex))
    {
        return BN_ptr(
            nullptr,
            BN_free);
    }

    hex = Trim(hex);

    return HexToScalar(hex);
}

/*-------------------------------------------------------------
    SavePointVector
--------------------------------------------------------------*/

bool SavePointVector(
        const ECCContext& ecc,
        const std::vector<const EC_POINT*>& points,
        const std::string& filename)
{
    std::vector<std::string> lines;

    lines.reserve(points.size());

    for(const auto* P : points)
    {
        if(P == nullptr)
            lines.emplace_back("");
        else
            lines.emplace_back(
                PointToHex(ecc,P));
    }

    return WriteLines(
            filename,
            lines);
}

/*-------------------------------------------------------------*/

std::vector<ECPoint_ptr>
LoadPointVector(
        const ECCContext& ecc,
        const std::string& filename)
{
    std::vector<ECPoint_ptr> result;

    auto lines =
        ReadLines(filename);

    result.reserve(lines.size());

    for(auto& line : lines)
    {
        line = Trim(line);

        if(line.empty())
        {
            result.emplace_back(
                nullptr,
                EC_POINT_free);
        }
        else
        {
            result.emplace_back(
                HexToPoint(
                    ecc,
                    line));
        }
    }

    return result;
}

/*-------------------------------------------------------------
    SaveScalarVector
--------------------------------------------------------------*/

bool SaveScalarVector(
        const std::vector<BN_ptr>& scalars,
        const std::string& filename)
{
    std::vector<std::string> lines;

    lines.reserve(scalars.size());

    for(const auto& s : scalars)
    {
        if(!s)
            lines.emplace_back("");
        else
            lines.emplace_back(
                ScalarToHex(
                    s.get()));
    }

    return WriteLines(
            filename,
            lines);
}

/*-------------------------------------------------------------*/

std::vector<BN_ptr>
LoadScalarVector(
        const std::string& filename)
{
    std::vector<BN_ptr> result;

    auto lines =
        ReadLines(filename);

    result.reserve(lines.size());

    for(auto& line : lines)
    {
        line = Trim(line);

        if(line.empty())
        {
            result.emplace_back(
                nullptr,
                BN_free);
        }
        else
        {
            result.emplace_back(
                HexToScalar(line));
        }
    }

    return result;
}
/*==============================================================
    Random Utility
==============================================================*/

/*-------------------------------------------------------------
    RandomString
--------------------------------------------------------------*/

std::string
RandomString(size_t length)
{
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    if(length == 0)
        return "";

    std::vector<unsigned char> rnd(length);

    if(RAND_bytes(
            rnd.data(),
            static_cast<int>(length)) != 1)
    {
        return "";
    }

    std::string result;

    result.reserve(length);

    constexpr size_t charsetSize =
        sizeof(charset) - 1;

    for(size_t i = 0; i < length; ++i)
    {
        result.push_back(
            charset[rnd[i] % charsetSize]);
    }

    return result;
}

/*-------------------------------------------------------------
    RandomUInt64
--------------------------------------------------------------*/

uint64_t
RandomUInt64()
{
    uint64_t value = 0;

    if(RAND_bytes(
            reinterpret_cast<unsigned char*>(&value),
            sizeof(value)) != 1)
    {
        return 0;
    }

    return value;
}

/*-------------------------------------------------------------
    RandomBytes
--------------------------------------------------------------*/

std::vector<unsigned char>
RandomBytes(size_t length)
{
    std::vector<unsigned char> buffer(length);

    if(length == 0)
        return buffer;

    if(RAND_bytes(
            buffer.data(),
            static_cast<int>(length)) != 1)
    {
        buffer.clear();
    }

    return buffer;
}

/*-------------------------------------------------------------
    RandomHex
--------------------------------------------------------------*/

std::string
RandomHex(size_t byteLength)
{
    auto bytes =
        RandomBytes(byteLength);

    if(bytes.empty())
        return "";

    return BytesToHex(bytes);
}

/*-------------------------------------------------------------
    RandomBool
--------------------------------------------------------------*/

bool
RandomBool()
{
    unsigned char b = 0;

    if(RAND_bytes(&b,1) != 1)
        return false;

    return (b & 0x01) != 0;
}

/*-------------------------------------------------------------
    RandomInt
--------------------------------------------------------------*/

int
RandomInt(
        int minValue,
        int maxValue)
{
    if(minValue >= maxValue)
        return minValue;

    uint32_t r = 0;

    if(RAND_bytes(
            reinterpret_cast<unsigned char*>(&r),
            sizeof(r)) != 1)
    {
        return minValue;
    }

    return minValue +
        static_cast<int>(
            r %
            static_cast<uint32_t>(
                maxValue - minValue + 1));
}

/*-------------------------------------------------------------
    RandomDouble
--------------------------------------------------------------*/

double
RandomDouble()
{
    uint64_t x =
        RandomUInt64();

    return static_cast<double>(x) /
           static_cast<double>(
               std::numeric_limits<uint64_t>::max());
}

/*-------------------------------------------------------------
    RandomIndex
--------------------------------------------------------------*/

size_t
RandomIndex(size_t upperBound)
{
    if(upperBound == 0)
        return 0;

    uint64_t r =
        RandomUInt64();

    return static_cast<size_t>(
            r % upperBound);
}
/*==============================================================
    Timer
==============================================================*/

/*-------------------------------------------------------------
    Constructor
--------------------------------------------------------------*/

Timer::Timer()
{
    start_ = std::chrono::high_resolution_clock::now();
    end_   = start_;
}

/*-------------------------------------------------------------
    Start
--------------------------------------------------------------*/

void Timer::Start()
{
    start_ =
        std::chrono::high_resolution_clock::now();
}

/*-------------------------------------------------------------
    Stop
--------------------------------------------------------------*/

void Timer::Stop()
{
    end_ =
        std::chrono::high_resolution_clock::now();
}

/*-------------------------------------------------------------
    Restart
--------------------------------------------------------------*/

void Timer::Restart()
{
    start_ =
        std::chrono::high_resolution_clock::now();

    end_ = start_;
}

/*-------------------------------------------------------------
    Seconds
--------------------------------------------------------------*/

double Timer::Seconds() const
{
    return std::chrono::duration<double>(
                end_ - start_).count();
}

/*-------------------------------------------------------------
    Milliseconds
--------------------------------------------------------------*/

double Timer::Milliseconds() const
{
    return std::chrono::duration<
                double,
                std::milli>(
                end_ - start_).count();
}

/*-------------------------------------------------------------
    Microseconds
--------------------------------------------------------------*/

double Timer::Microseconds() const
{
    return std::chrono::duration<
                double,
                std::micro>(
                end_ - start_).count();
}

/*-------------------------------------------------------------
    Nanoseconds
--------------------------------------------------------------*/

double Timer::Nanoseconds() const
{
    return std::chrono::duration<
                double,
                std::nano>(
                end_ - start_).count();
}

/*==============================================================
    Benchmark Utility
==============================================================*/

/*-------------------------------------------------------------
    Measure Once
--------------------------------------------------------------*/

double Measure(
        const std::function<void()>& func)
{
    Timer timer;

    timer.Start();

    func();

    timer.Stop();

    return timer.Milliseconds();
}

/*-------------------------------------------------------------
    Average Time
--------------------------------------------------------------*/

double AverageTime(
        const std::function<void()>& func,
        size_t repeat)
{
    if(repeat == 0)
        return 0.0;

    double total = 0.0;

    for(size_t i = 0; i < repeat; ++i)
    {
        total += Measure(func);
    }

    return total /
           static_cast<double>(repeat);
}

/*-------------------------------------------------------------
    Min Time
--------------------------------------------------------------*/

double MinTime(
        const std::function<void()>& func,
        size_t repeat)
{
    if(repeat == 0)
        return 0.0;

    double best =
        std::numeric_limits<double>::max();

    for(size_t i = 0; i < repeat; ++i)
    {
        best =
            std::min(
                best,
                Measure(func));
    }

    return best;
}

/*-------------------------------------------------------------
    Max Time
--------------------------------------------------------------*/

double MaxTime(
        const std::function<void()>& func,
        size_t repeat)
{
    if(repeat == 0)
        return 0.0;

    double worst = 0.0;

    for(size_t i = 0; i < repeat; ++i)
    {
        worst =
            std::max(
                worst,
                Measure(func));
    }

    return worst;
}
/*==============================================================
    Console Output
==============================================================*/

/*-------------------------------------------------------------
    PrintTitle
--------------------------------------------------------------*/

void PrintTitle(
        const std::string& title)
{
    std::cout << std::endl;

    std::cout
        << "============================================================"
        << std::endl;

    std::cout
        << title
        << std::endl;

    std::cout
        << "============================================================"
        << std::endl;
}

/*-------------------------------------------------------------
    PrintSeparator
--------------------------------------------------------------*/

void PrintSeparator()
{
    std::cout
        << "------------------------------------------------------------"
        << std::endl;
}

/*-------------------------------------------------------------
    PrintMessage
--------------------------------------------------------------*/

void PrintMessage(
        const std::string& message)
{
    std::cout
        << message
        << std::endl;
}

/*-------------------------------------------------------------
    PrintScalar
--------------------------------------------------------------*/

void PrintScalar(
        const BIGNUM* scalar)
{
    if(scalar == nullptr)
    {
        std::cout
            << "<NULL>"
            << std::endl;

        return;
    }

    std::cout
        << ScalarToHex(scalar)
        << std::endl;
}

/*-------------------------------------------------------------
    PrintPoint
--------------------------------------------------------------*/

void PrintPoint(
        const ECCContext& ecc,
        const EC_POINT* point)
{
    if(point == nullptr)
    {
        std::cout
            << "<NULL>"
            << std::endl;

        return;
    }

    std::cout
        << PointToHex(
                ecc,
                point)
        << std::endl;
}

/*-------------------------------------------------------------
    PrintBytes
--------------------------------------------------------------*/

void PrintBytes(
        const std::vector<unsigned char>& bytes)
{
    if(bytes.empty())
    {
        std::cout
            << "<EMPTY>"
            << std::endl;

        return;
    }

    std::cout
        << BytesToHex(bytes)
        << std::endl;
}

/*-------------------------------------------------------------
    PrintStringVector
--------------------------------------------------------------*/

void PrintStringVector(
        const std::vector<std::string>& vec)
{
    if(vec.empty())
    {
        std::cout
            << "<EMPTY>"
            << std::endl;

        return;
    }

    for(size_t i = 0; i < vec.size(); ++i)
    {
        std::cout
            << "[" << i << "] "
            << vec[i]
            << std::endl;
    }
}

/*-------------------------------------------------------------
    PrintScalarVector
--------------------------------------------------------------*/

void PrintScalarVector(
        const std::vector<BN_ptr>& vec)
{
    if(vec.empty())
    {
        std::cout
            << "<EMPTY>"
            << std::endl;

        return;
    }

    for(size_t i = 0; i < vec.size(); ++i)
    {
        std::cout
            << "[" << i << "] ";

        if(vec[i])
            std::cout
                << ScalarToHex(vec[i].get());
        else
            std::cout
                << "<NULL>";

        std::cout
            << std::endl;
    }
}

/*-------------------------------------------------------------
    PrintPointVector
--------------------------------------------------------------*/

void PrintPointVector(
        const ECCContext& ecc,
        const std::vector<ECPoint_ptr>& vec)
{
    if(vec.empty())
    {
        std::cout
            << "<EMPTY>"
            << std::endl;

        return;
    }

    for(size_t i = 0; i < vec.size(); ++i)
    {
        std::cout
            << "[" << i << "] ";

        if(vec[i])
            std::cout
                << PointToHex(
                        ecc,
                        vec[i].get());
        else
            std::cout
                << "<NULL>";

        std::cout
            << std::endl;
    }
}

/*-------------------------------------------------------------
    PrintHeaderInfo
--------------------------------------------------------------*/

void PrintHeaderInfo(
        const HeaderInfo& header)
{
    PrintSeparator();

    std::cout
        << "Policy       : "
        << header.policy
        << std::endl;

    std::cout
        << "Rows         : "
        << header.rows
        << std::endl;

    std::cout
        << "Columns      : "
        << header.cols
        << std::endl;

    std::cout
        << "Users        : "
        << header.userCount
        << std::endl;

    std::cout
        << "Groups       : "
        << header.groupCount
        << std::endl;

    PrintSeparator();
}

/*-------------------------------------------------------------
    PrintMatrix
--------------------------------------------------------------*/

void PrintMatrix(
        const std::vector<std::vector<int>>& M)
{
    std::cout
        << "Access Matrix"
        << std::endl;

    for(const auto& row : M)
    {
        for(auto x : row)
        {
            std::cout
                << std::setw(4)
                << x;
        }

        std::cout
            << std::endl;
    }
}

/*-------------------------------------------------------------
    PrintPolicy
--------------------------------------------------------------*/

void PrintPolicy(
        const std::string& policy)
{
    std::cout
        << "Policy : "
        << policy
        << std::endl;
}
/*==============================================================
    Debug & Misc
==============================================================*/

/*-------------------------------------------------------------
    CheckOpenSSLError
--------------------------------------------------------------*/

void CheckOpenSSLError()
{
    unsigned long err;

    while((err = ERR_get_error()) != 0)
    {
        char buffer[256];

        ERR_error_string_n(
                err,
                buffer,
                sizeof(buffer));

        std::cerr
            << "[OpenSSL] "
            << buffer
            << std::endl;
    }
}

/*-------------------------------------------------------------
    Assert
--------------------------------------------------------------*/

void Assert(
        bool condition,
        const std::string& message)
{
    if(condition)
        return;

    std::cerr
        << "[ASSERT] "
        << message
        << std::endl;

    CheckOpenSSLError();

    throw std::runtime_error(message);
}

/*-------------------------------------------------------------
    FileExists
--------------------------------------------------------------*/

bool FileExists(
        const std::string& filename)
{
    std::ifstream ifs(filename);

    return ifs.good();
}

/*-------------------------------------------------------------
    CurrentTime
--------------------------------------------------------------*/

std::string CurrentTime()
{
    auto now =
        std::chrono::system_clock::now();

    auto tt =
        std::chrono::system_clock::to_time_t(now);

    std::tm tm{};

#ifdef _WIN32
    localtime_s(&tm,&tt);
#else
    localtime_r(&tt,&tm);
#endif

    std::ostringstream oss;

    oss << std::put_time(
            &tm,
            "%Y-%m-%d %H:%M:%S");

    return oss.str();
}

/*-------------------------------------------------------------
    PrintBanner
--------------------------------------------------------------*/

void PrintBanner()
{
    std::cout
    << "============================================================\n"
    << "      Broadcast Encryption based on ECC\n"
    << "------------------------------------------------------------\n"
    << " Curve        : prime256v1 (secp256r1)\n"
    << " ECC Library  : OpenSSL 3.x\n"
    << " Hash         : SHA-256\n"
    << " Security     : 128-bit\n"
    << "============================================================\n";
}

/*-------------------------------------------------------------
    PrintSuccess
--------------------------------------------------------------*/

void PrintSuccess(
        const std::string& message)
{
    std::cout
        << "[SUCCESS] "
        << message
        << std::endl;
}

/*-------------------------------------------------------------
    PrintError
--------------------------------------------------------------*/

void PrintError(
        const std::string& message)
{
    std::cerr
        << "[ERROR] "
        << message
        << std::endl;
}

/*-------------------------------------------------------------
    IsZero
--------------------------------------------------------------*/

bool IsZero(
        const BIGNUM* bn)
{
    if(bn == nullptr)
        return false;

    return BN_is_zero(bn);
}

/*-------------------------------------------------------------
    IsOne
--------------------------------------------------------------*/

bool IsOne(
        const BIGNUM* bn)
{
    if(bn == nullptr)
        return false;

    return BN_is_one(bn);
}

/*-------------------------------------------------------------
    CompareBN
--------------------------------------------------------------*/

bool CompareBN(
        const BIGNUM* a,
        const BIGNUM* b)
{
    if(a == nullptr || b == nullptr)
        return false;

    return BN_cmp(a,b)==0;
}

/*-------------------------------------------------------------
    CopyScalar
--------------------------------------------------------------*/

BN_ptr CopyScalar(
        const BIGNUM* bn)
{
    if(bn == nullptr)
    {
        return BN_ptr(
                nullptr,
                BN_free);
    }

    return BN_ptr(
            BN_dup(bn),
            BN_free);
}

/*-------------------------------------------------------------
    CopyPoint
--------------------------------------------------------------*/

ECPoint_ptr CopyPoint(
        const ECCContext& ecc,
        const EC_POINT* point)
{
    if(point == nullptr)
    {
        return ECPoint_ptr(
                nullptr,
                EC_POINT_free);
    }

    return ECPoint_ptr(
            EC_POINT_dup(
                point,
                ecc.Group()),
            EC_POINT_free);
}

} // namespace BE