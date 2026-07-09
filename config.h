#ifndef BE_CONFIG_H
#define BE_CONFIG_H

/********************************************************************
 *
 *  Broadcast Encryption based on Elliptic Curve Cryptography
 *
 *  Configuration File
 *
 *  Curve      : secp256r1 (prime256v1)
 *  Library    : OpenSSL 3.x
 *  Compiler   : C++17
 *
 ********************************************************************/

#include <string>
#include <cstddef>

namespace BE
{

/*==============================================================
    Version
==============================================================*/

constexpr char PROJECT_NAME[] = "ECC Broadcast Encryption";

constexpr char PROJECT_VERSION[] = "1.0";

/*==============================================================
    Elliptic Curve
==============================================================*/

constexpr char CURVE_NAME[] = "prime256v1";

/* OpenSSL NID */
constexpr int CURVE_NID = 415;        // NID_X9_62_prime256v1

/*==============================================================
    Security
==============================================================*/

constexpr int SECURITY_LEVEL = 128;

constexpr int HASH_SIZE = 32;         // SHA-256

constexpr int SCALAR_SIZE = 32;

constexpr int COMPRESSED_POINT_SIZE = 33;

constexpr int UNCOMPRESSED_POINT_SIZE = 65;

/*==============================================================
    Random
==============================================================*/

constexpr int RANDOM_SEED_SIZE = 32;

/*==============================================================
    Hash
==============================================================*/

constexpr char HASH_FUNCTION[] = "SHA256";

/*==============================================================
    File Extension
==============================================================*/

constexpr char PUBLIC_KEY_EXTENSION[] = ".pk";

constexpr char SECRET_KEY_EXTENSION[] = ".sk";

constexpr char HEADER_EXTENSION[] = ".hdr";

constexpr char PARAMETER_EXTENSION[] = ".param";

/*==============================================================
    Folder
==============================================================*/

constexpr char OUTPUT_DIRECTORY[] = "output/";

constexpr char PUBLIC_KEY_DIRECTORY[] = "output/public_key/";

constexpr char SECRET_KEY_DIRECTORY[] = "output/secret_key/";

constexpr char HEADER_DIRECTORY[] = "output/header/";

constexpr char PARAMETER_DIRECTORY[] = "output/parameter/";

/*==============================================================
    Logging
==============================================================*/

constexpr bool ENABLE_LOG = true;

constexpr bool ENABLE_TIMER = true;

constexpr bool ENABLE_DEBUG = true;

/*==============================================================
    Serialization
==============================================================*/

constexpr bool USE_COMPRESSED_POINT = true;

constexpr bool SAVE_AS_TEXT = true;

/*==============================================================
    Default Parameters
==============================================================*/

constexpr std::size_t DEFAULT_USER_NUMBER = 100;

constexpr std::size_t DEFAULT_GROUP_NUMBER = 10;

constexpr std::size_t DEFAULT_THRESHOLD = 5;

/*==============================================================
    Benchmark
==============================================================*/

constexpr int DEFAULT_REPEAT = 30;

/*==============================================================
    Policy
==============================================================*/

constexpr char OP_AND[] = "AND";

constexpr char OP_OR[] = "OR";

/*==============================================================
    Return Code
==============================================================*/

enum class Status
{
    SUCCESS = 0,

    FAILED,

    INVALID_PARAMETER,

    INVALID_POINT,

    INVALID_SCALAR,

    FILE_ERROR,

    HASH_ERROR,

    ECC_ERROR,

    LSS_ERROR
};

} // namespace BE

#endif