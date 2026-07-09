#ifndef BE_ECC_H
#define BE_ECC_H

/********************************************************************
*
*   ecc.h
*
*   Elliptic Curve Utility
*
*   Curve:
*       secp256r1
*
*   Library:
*       OpenSSL 3.x
*
********************************************************************/

#include "config.h"
#include "types.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <memory>
#include <vector>
#include <string>

namespace BE
{

/*==============================================================
    Smart Pointer
==============================================================*/

using BN_ptr =
    std::unique_ptr<BIGNUM, decltype(&BN_free)>;

using ECPoint_ptr =
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

/*==============================================================
    ECC Context
==============================================================*/

class ECCContext
{
public:

    ECCContext();

    ~ECCContext();

    bool Initialize();

    EC_GROUP* Group() const;

    BN_CTX* Context() const;

    const EC_POINT* Generator() const;

    const BIGNUM* Order() const;

private:

    EC_GROUP* group_;

    BN_CTX* bn_ctx_;

    BIGNUM* order_;
};

/*==============================================================
    Random Scalar
==============================================================*/

BN_ptr RandomScalar(
        const ECCContext& ecc);

BN_ptr RandomNonZeroScalar(
        const ECCContext& ecc);

/*==============================================================
    Scalar Arithmetic
==============================================================*/

BN_ptr ScalarAdd(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b);

BN_ptr ScalarSub(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b);

BN_ptr ScalarMul(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b);

BN_ptr ScalarInverse(
        const ECCContext& ecc,
        const BIGNUM* a);

BN_ptr ScalarDiv(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b);

/*==============================================================
    Point Arithmetic
==============================================================*/

ECPoint_ptr GeneratorMul(
        const ECCContext& ecc,
        const BIGNUM* k);

ECPoint_ptr PointMul(
        const ECCContext& ecc,
        const EC_POINT* P,
        const BIGNUM* k);

ECPoint_ptr PointAdd(
        const ECCContext& ecc,
        const EC_POINT* P,
        const EC_POINT* Q);

ECPoint_ptr PointSub(
        const ECCContext& ecc,
        const EC_POINT* P,
        const EC_POINT* Q);

ECPoint_ptr PointInverse(
        const ECCContext& ecc,
        const EC_POINT* P);

bool PointEqual(
        const ECCContext& ecc,
        const EC_POINT* P,
        const EC_POINT* Q);

/*==============================================================
    Serialization
==============================================================*/

std::string PointToHex(
        const ECCContext& ecc,
        const EC_POINT* P,
        point_conversion_form_t form =
            POINT_CONVERSION_COMPRESSED);

ECPoint_ptr HexToPoint(
        const ECCContext& ecc,
        const std::string& hex);

std::string ScalarToHex(
        const BIGNUM* bn);

BN_ptr HexToScalar(
        const std::string& hex);

/*==============================================================
    Hash
==============================================================*/

BN_ptr HashToScalar(
        const ECCContext& ecc,
        const std::string& message);

ECPoint_ptr HashToPoint(
        const ECCContext& ecc,
        const std::string& message);

/*==============================================================
    Validation
==============================================================*/

bool CheckPoint(
        const ECCContext& ecc,
        const EC_POINT* P);

bool CheckScalar(
        const ECCContext& ecc,
        const BIGNUM* x);

bool IsInfinity(
        const ECCContext& ecc,
        const EC_POINT* P);

/*==============================================================
    Batch Operations
==============================================================*/

std::vector<ECPoint_ptr>
MultiGeneratorMul(
        const ECCContext& ecc,
        const std::vector<BN_ptr>& scalars);

ECPoint_ptr MultiPointAdd(
        const ECCContext& ecc,
        const std::vector<const EC_POINT*>& points);

} // namespace BE

#endif