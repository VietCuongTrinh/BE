#ifndef BE_TYPES_H
#define BE_TYPES_H

#include <memory>
#include <vector>
#include <string>
#include <unordered_map>

#include <openssl/bn.h>
#include <openssl/ec.h>

namespace BE
{

class ECCContext;

/*==============================================================
    Smart Pointer
==============================================================*/

using BN_ptr =
    std::unique_ptr<BIGNUM, decltype(&BN_free)>;

using ECPoint_ptr =
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

/*==============================================================
    Public Key Entry
==============================================================*/

struct PublicKeyEntry
{
    uint32_t id;

    std::string name;

    EC_POINT* pk;

    PublicKeyEntry()
        : id(0),
          pk(nullptr)
    {
    }
};

/*==============================================================
    Public Parameters
==============================================================*/

struct PublicParameters
{
    std::shared_ptr<ECCContext> ecc;

    EC_POINT* G;

    BIGNUM* order;

    /*
        Public-key directory
    */

    std::unordered_map<
            uint32_t,
            PublicKeyEntry> directory;

    PublicParameters()
        : G(nullptr),
          order(nullptr)
    {
    }
};

/*==============================================================
    User
==============================================================*/

struct User
{
    uint32_t id;

    std::string name;

    /*
        Secret key
    */

    BIGNUM* sk;

    /*
        Public key
    */

    EC_POINT* pk;

    User()
        : id(0),
          sk(nullptr),
          pk(nullptr)
    {
    }
};

/*==============================================================
    LSS Matrix
==============================================================*/

struct LSSMatrix
{
    std::vector<
        std::vector<BN_ptr>> matrix;

    std::vector<std::string> rho;

    void Clear()
    {
        matrix.clear();
        rho.clear();
    }

    size_t Rows() const
    {
        return matrix.size();
    }

    size_t Cols() const
    {
        if(matrix.empty())
            return 0;

        return matrix[0].size();
    }
};

/*==============================================================
    Header
==============================================================*/

struct Header
{
    /*
        Ciphertext components

        Ci=g^{λi·aρ(i)}
    */

    std::vector<EC_POINT*> C;

    /*
        LSS
    */

    LSSMatrix matrix;

    /*
        Target groups
    */

    std::vector<
        std::vector<uint32_t>> groups;

    void Clear()
    {
        for(auto p : C)
        {
            if(p)
                EC_POINT_free(p);
        }

        C.clear();

        matrix.Clear();

        groups.clear();
    }
};

/*==============================================================
    Partial Session Key
==============================================================*/

struct PartialKey
{
    uint32_t id;

    EC_POINT* value;

    PartialKey()
        : id(0),
          value(nullptr)
    {
    }
};

/*==============================================================
    Session Key
==============================================================*/

struct SessionKey
{
    EC_POINT* K;

    SessionKey()
        : K(nullptr)
    {
    }
};

}

#endif