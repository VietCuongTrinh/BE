/********************************************************************
*
*   ecc.cpp
*
*   Elliptic Curve Utility
*
********************************************************************/

#include "ecc.h"

#include <openssl/err.h>

#include <iostream>

namespace BE
{

/*==============================================================
    ECCContext
==============================================================*/

ECCContext::ECCContext()
    : group_(nullptr),
      bn_ctx_(nullptr),
      order_(nullptr)
{

}

/*-------------------------------------------------------------*/

ECCContext::~ECCContext()
{
    if(order_ != nullptr)
    {
        BN_free(order_);
        order_ = nullptr;
    }

    if(group_ != nullptr)
    {
        EC_GROUP_free(group_);
        group_ = nullptr;
    }

    if(bn_ctx_ != nullptr)
    {
        BN_CTX_free(bn_ctx_);
        bn_ctx_ = nullptr;
    }
}

/*-------------------------------------------------------------*/

bool ECCContext::Initialize()
{
    /*-----------------------------------------
        BN Context
    -----------------------------------------*/

    bn_ctx_ = BN_CTX_new();

    if(bn_ctx_ == nullptr)
        return false;

    /*-----------------------------------------
        Elliptic Curve
    -----------------------------------------*/

    group_ =
        EC_GROUP_new_by_curve_name(
                CURVE_NID);

    if(group_ == nullptr)
        return false;

    EC_GROUP_set_asn1_flag(
            group_,
            OPENSSL_EC_NAMED_CURVE);

    /*-----------------------------------------
        Group Order
    -----------------------------------------*/

    order_ = BN_new();

    if(order_ == nullptr)
        return false;

    if(!EC_GROUP_get_order(
            group_,
            order_,
            bn_ctx_))
    {
        return false;
    }

    return true;
}

/*==============================================================
    Getter
==============================================================*/

EC_GROUP*
ECCContext::Group() const
{
    return group_;
}

/*-------------------------------------------------------------*/

BN_CTX*
ECCContext::Context() const
{
    return bn_ctx_;
}

/*-------------------------------------------------------------*/

const EC_POINT*
ECCContext::Generator() const
{
    return EC_GROUP_get0_generator(group_);
}

/*-------------------------------------------------------------*/

const BIGNUM*
ECCContext::Order() const
{
    return order_;
}

} // namespace BE
/*==============================================================
    Random Scalar
==============================================================*/

BN_ptr RandomScalar(
        const ECCContext& ecc)
{
    BN_ptr k(
        BN_new(),
        BN_free);

    if(!k)
    {
        return BN_ptr(
            nullptr,
            BN_free);
    }

    if(!BN_rand_range(
            k.get(),
            ecc.Order()))
    {
        return BN_ptr(
            nullptr,
            BN_free);
    }

    return k;
}

/*-------------------------------------------------------------*/

BN_ptr RandomNonZeroScalar(
        const ECCContext& ecc)
{
    BN_ptr k(
        BN_new(),
        BN_free);

    if(!k)
    {
        return BN_ptr(
            nullptr,
            BN_free);
    }

    do
    {
        if(!BN_rand_range(
                k.get(),
                ecc.Order()))
        {
            return BN_ptr(
                nullptr,
                BN_free);
        }

    } while(BN_is_zero(k.get()));

    return k;
}
/*==============================================================
    Scalar Addition
==============================================================*/

BN_ptr ScalarAdd(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b)
{
    BN_ptr result(
        BN_new(),
        BN_free);

    if(!result)
        return BN_ptr(nullptr, BN_free);

    if(!BN_mod_add(
            result.get(),
            a,
            b,
            ecc.Order(),
            ecc.Context()))
    {
        return BN_ptr(nullptr, BN_free);
    }

    return result;
}

/*-------------------------------------------------------------*/

BN_ptr ScalarSub(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b)
{
    BN_ptr result(
        BN_new(),
        BN_free);

    if(!result)
        return BN_ptr(nullptr, BN_free);

    if(!BN_mod_sub(
            result.get(),
            a,
            b,
            ecc.Order(),
            ecc.Context()))
    {
        return BN_ptr(nullptr, BN_free);
    }

    return result;
}

/*-------------------------------------------------------------*/

BN_ptr ScalarMul(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b)
{
    BN_ptr result(
        BN_new(),
        BN_free);

    if(!result)
        return BN_ptr(nullptr, BN_free);

    if(!BN_mod_mul(
            result.get(),
            a,
            b,
            ecc.Order(),
            ecc.Context()))
    {
        return BN_ptr(nullptr, BN_free);
    }

    return result;
}

/*-------------------------------------------------------------*/

BN_ptr ScalarInverse(
        const ECCContext& ecc,
        const BIGNUM* a)
{
    BIGNUM* inv =
        BN_mod_inverse(
            nullptr,
            a,
            ecc.Order(),
            ecc.Context());

    if(inv == nullptr)
    {
        return BN_ptr(nullptr, BN_free);
    }

    return BN_ptr(inv, BN_free);
}

/*-------------------------------------------------------------*/

BN_ptr ScalarDiv(
        const ECCContext& ecc,
        const BIGNUM* a,
        const BIGNUM* b)
{
    auto inv =
        ScalarInverse(
            ecc,
            b);

    if(!inv)
    {
        return BN_ptr(nullptr, BN_free);
    }

    return ScalarMul(
            ecc,
            a,
            inv.get());
}
/*==============================================================
    Generator Multiplication
==============================================================*/

ECPoint_ptr GeneratorMul(
        const ECCContext& ecc,
        const BIGNUM* k)
{
    ECPoint_ptr P(
        EC_POINT_new(ecc.Group()),
        EC_POINT_free);

    if(!P)
        return ECPoint_ptr(nullptr, EC_POINT_free);

    if(!EC_POINT_mul(
            ecc.Group(),
            P.get(),
            k,
            nullptr,
            nullptr,
            ecc.Context()))
    {
        return ECPoint_ptr(nullptr, EC_POINT_free);
    }

    return P;
}

/*-------------------------------------------------------------*/

ECPoint_ptr PointMul(
        const ECCContext& ecc,
        const EC_POINT* P,
        const BIGNUM* k)
{
    ECPoint_ptr R(
        EC_POINT_new(ecc.Group()),
        EC_POINT_free);

    if(!R)
        return ECPoint_ptr(nullptr, EC_POINT_free);

    if(!EC_POINT_mul(
            ecc.Group(),
            R.get(),
            nullptr,
            P,
            k,
            ecc.Context()))
    {
        return ECPoint_ptr(nullptr, EC_POINT_free);
    }

    return R;
}

/*-------------------------------------------------------------*/

ECPoint_ptr PointAdd(
        const ECCContext& ecc,
        const EC_POINT* P,
        const EC_POINT* Q)
{
    ECPoint_ptr R(
        EC_POINT_new(ecc.Group()),
        EC_POINT_free);

    if(!R)
        return ECPoint_ptr(nullptr, EC_POINT_free);

    if(!EC_POINT_add(
            ecc.Group(),
            R.get(),
            P,
            Q,
            ecc.Context()))
    {
        return ECPoint_ptr(nullptr, EC_POINT_free);
    }

    return R;
}

/*-------------------------------------------------------------*/

ECPoint_ptr PointInverse(
        const ECCContext& ecc,
        const EC_POINT* P)
{
    ECPoint_ptr R(
        EC_POINT_dup(P, ecc.Group()),
        EC_POINT_free);

    if(!R)
        return ECPoint_ptr(nullptr, EC_POINT_free);

    if(!EC_POINT_invert(
            ecc.Group(),
            R.get(),
            ecc.Context()))
    {
        return ECPoint_ptr(nullptr, EC_POINT_free);
    }

    return R;
}

/*-------------------------------------------------------------*/

ECPoint_ptr PointSub(
        const ECCContext& ecc,
        const EC_POINT* P,
        const EC_POINT* Q)
{
    auto negQ =
        PointInverse(
            ecc,
            Q);

    if(!negQ)
        return ECPoint_ptr(nullptr, EC_POINT_free);

    return PointAdd(
            ecc,
            P,
            negQ.get());
}

/*-------------------------------------------------------------*/

bool PointEqual(
        const ECCContext& ecc,
        const EC_POINT* P,
        const EC_POINT* Q)
{
    if(P == nullptr || Q == nullptr)
        return false;

    return EC_POINT_cmp(
                ecc.Group(),
                P,
                Q,
                ecc.Context()) == 0;
}
/*==============================================================
    Point -> Hex
==============================================================*/

std::string PointToHex(
        const ECCContext& ecc,
        const EC_POINT* P,
        point_conversion_form_t form)
{
    if(P == nullptr)
        return "";

    char* hex =
        EC_POINT_point2hex(
            ecc.Group(),
            P,
            form,
            ecc.Context());

    if(hex == nullptr)
        return "";

    std::string result(hex);

    OPENSSL_free(hex);

    return result;
}

/*-------------------------------------------------------------*/

ECPoint_ptr HexToPoint(
        const ECCContext& ecc,
        const std::string& hex)
{
    ECPoint_ptr P(
        EC_POINT_new(ecc.Group()),
        EC_POINT_free);

    if(!P)
    {
        return ECPoint_ptr(
            nullptr,
            EC_POINT_free);
    }

    if(!EC_POINT_hex2point(
            ecc.Group(),
            hex.c_str(),
            P.get(),
            ecc.Context()))
    {
        return ECPoint_ptr(
            nullptr,
            EC_POINT_free);
    }

    return P;
}

/*==============================================================
    Scalar -> Hex
==============================================================*/

std::string ScalarToHex(
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

BN_ptr HexToScalar(
        const std::string& hex)
{
    BIGNUM* bn = nullptr;

    if(BN_hex2bn(
            &bn,
            hex.c_str()) == 0)
    {
        return BN_ptr(
            nullptr,
            BN_free);
    }

    return BN_ptr(
            bn,
            BN_free);
}

/*==============================================================
    Point -> Bytes
==============================================================*/

std::vector<unsigned char>
PointToBytes(
        const ECCContext& ecc,
        const EC_POINT* P)
{
    std::vector<unsigned char> buffer;

    if(P == nullptr)
        return buffer;

    size_t len =
        EC_POINT_point2oct(
            ecc.Group(),
            P,
            POINT_CONVERSION_COMPRESSED,
            nullptr,
            0,
            ecc.Context());

    buffer.resize(len);

    EC_POINT_point2oct(
            ecc.Group(),
            P,
            POINT_CONVERSION_COMPRESSED,
            buffer.data(),
            buffer.size(),
            ecc.Context());

    return buffer;
}

/*-------------------------------------------------------------*/

ECPoint_ptr BytesToPoint(
        const ECCContext& ecc,
        const std::vector<unsigned char>& bytes)
{
    ECPoint_ptr P(
        EC_POINT_new(ecc.Group()),
        EC_POINT_free);

    if(!P)
        return ECPoint_ptr(nullptr,
                           EC_POINT_free);

    if(!EC_POINT_oct2point(
            ecc.Group(),
            P.get(),
            bytes.data(),
            bytes.size(),
            ecc.Context()))
    {
        return ECPoint_ptr(nullptr,
                           EC_POINT_free);
    }

    return P;
}
/*==============================================================
    HashToScalar
==============================================================*/

BN_ptr HashToScalar(
        const ECCContext& ecc,
        const std::string& message)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256(
        reinterpret_cast<const unsigned char*>(
            message.data()),
        message.size(),
        digest);

    BIGNUM* h =
        BN_bin2bn(
            digest,
            SHA256_DIGEST_LENGTH,
            nullptr);

    if(h == nullptr)
    {
        return BN_ptr(nullptr, BN_free);
    }

    BN_ptr result(
        h,
        BN_free);

    if(!BN_mod(
            result.get(),
            result.get(),
            ecc.Order(),
            ecc.Context()))
    {
        return BN_ptr(nullptr, BN_free);
    }

    /*
        Avoid zero.
    */

    if(BN_is_zero(result.get()))
    {
        BN_one(result.get());
    }

    return result;
}

/*-------------------------------------------------------------*/

ECPoint_ptr HashToPoint(
        const ECCContext& ecc,
        const std::string& message)
{
    auto h =
        HashToScalar(
            ecc,
            message);

    if(!h)
    {
        return ECPoint_ptr(
                nullptr,
                EC_POINT_free);
    }

    return GeneratorMul(
            ecc,
            h.get());
}

/*==============================================================
    Hash Multiple Strings
==============================================================*/

BN_ptr HashToScalar(
        const ECCContext& ecc,
        const std::vector<std::string>& messages)
{
    SHA256_CTX sha;

    SHA256_Init(&sha);

    for(const auto& s : messages)
    {
        SHA256_Update(
            &sha,
            s.data(),
            s.size());
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256_Final(
        digest,
        &sha);

    BIGNUM* h =
        BN_bin2bn(
            digest,
            SHA256_DIGEST_LENGTH,
            nullptr);

    if(h == nullptr)
    {
        return BN_ptr(nullptr, BN_free);
    }

    BN_ptr result(
        h,
        BN_free);

    BN_mod(
        result.get(),
        result.get(),
        ecc.Order(),
        ecc.Context());

    if(BN_is_zero(result.get()))
    {
        BN_one(result.get());
    }

    return result;
}

/*-------------------------------------------------------------*/

ECPoint_ptr HashToPoint(
        const ECCContext& ecc,
        const std::vector<std::string>& messages)
{
    auto h =
        HashToScalar(
            ecc,
            messages);

    if(!h)
    {
        return ECPoint_ptr(
                nullptr,
                EC_POINT_free);
    }

    return GeneratorMul(
            ecc,
            h.get());
}
/*==============================================================
    Validation
==============================================================*/

/*-------------------------------------------------------------
    Check Scalar
--------------------------------------------------------------*/

bool CheckScalar(
        const ECCContext& ecc,
        const BIGNUM* x)
{
    if(x == nullptr)
        return false;

    /* x > 0 */
    if(BN_is_zero(x))
        return false;

    /* x < q */
    if(BN_cmp(x, ecc.Order()) >= 0)
        return false;

    return true;
}

/*-------------------------------------------------------------*/

bool CheckPoint(
        const ECCContext& ecc,
        const EC_POINT* P)
{
    if(P == nullptr)
        return false;

    /*
        Point must belong to the curve
    */
    if(!EC_POINT_is_on_curve(
            ecc.Group(),
            P,
            ecc.Context()))
    {
        return false;
    }

    /*
        Infinity is not allowed
    */
    if(EC_POINT_is_at_infinity(
            ecc.Group(),
            P))
    {
        return false;
    }

    return true;
}

/*-------------------------------------------------------------*/

bool IsInfinity(
        const ECCContext& ecc,
        const EC_POINT* P)
{
    if(P == nullptr)
        return true;

    return EC_POINT_is_at_infinity(
            ecc.Group(),
            P);
}

/*==============================================================
    Copy
==============================================================*/

BN_ptr CopyScalar(
        const BIGNUM* x)
{
    if(x == nullptr)
    {
        return BN_ptr(
            nullptr,
            BN_free);
    }

    return BN_ptr(
            BN_dup(x),
            BN_free);
}

/*-------------------------------------------------------------*/

ECPoint_ptr CopyPoint(
        const ECCContext& ecc,
        const EC_POINT* P)
{
    if(P == nullptr)
    {
        return ECPoint_ptr(
                nullptr,
                EC_POINT_free);
    }

    return ECPoint_ptr(
            EC_POINT_dup(
                P,
                ecc.Group()),
            EC_POINT_free);
}

/*==============================================================
    Comparison
==============================================================*/

bool ScalarEqual(
        const BIGNUM* a,
        const BIGNUM* b)
{
    if(a == nullptr || b == nullptr)
        return false;

    return BN_cmp(a,b)==0;
}

/*-------------------------------------------------------------*/

bool PointIsGenerator(
        const ECCContext& ecc,
        const EC_POINT* P)
{
    if(P==nullptr)
        return false;

    return EC_POINT_cmp(
            ecc.Group(),
            P,
            ecc.Generator(),
            ecc.Context())==0;
}
/*==============================================================
    Batch Operations
==============================================================*/

/*-------------------------------------------------------------
    MultiGeneratorMul
--------------------------------------------------------------*/

std::vector<ECPoint_ptr>
MultiGeneratorMul(
        const ECCContext& ecc,
        const std::vector<BN_ptr>& scalars)
{
    std::vector<ECPoint_ptr> result;

    result.reserve(scalars.size());

    for(const auto& k : scalars)
    {
        if(!k)
        {
            result.emplace_back(
                nullptr,
                EC_POINT_free);
            continue;
        }

        result.emplace_back(
            GeneratorMul(
                ecc,
                k.get()));
    }

    return result;
}

/*-------------------------------------------------------------
    MultiPointAdd
--------------------------------------------------------------*/

ECPoint_ptr
MultiPointAdd(
        const ECCContext& ecc,
        const std::vector<const EC_POINT*>& points)
{
    ECPoint_ptr sum(
        EC_POINT_new(ecc.Group()),
        EC_POINT_free);

    if(!sum)
    {
        return ECPoint_ptr(
            nullptr,
            EC_POINT_free);
    }

    /*
        Identity element
    */

    if(!EC_POINT_set_to_infinity(
            ecc.Group(),
            sum.get()))
    {
        return ECPoint_ptr(
            nullptr,
            EC_POINT_free);
    }

    for(const auto* P : points)
    {
        if(P == nullptr)
            continue;

        if(!EC_POINT_add(
                ecc.Group(),
                sum.get(),
                sum.get(),
                P,
                ecc.Context()))
        {
            return ECPoint_ptr(
                nullptr,
                EC_POINT_free);
        }
    }

    return sum;
}

/*-------------------------------------------------------------
    MultiPointMul
--------------------------------------------------------------*/

std::vector<ECPoint_ptr>
MultiPointMul(
        const ECCContext& ecc,
        const std::vector<const EC_POINT*>& points,
        const std::vector<BN_ptr>& scalars)
{
    std::vector<ECPoint_ptr> result;

    if(points.size() != scalars.size())
        return result;

    result.reserve(points.size());

    for(size_t i = 0; i < points.size(); ++i)
    {
        if(points[i] == nullptr || !scalars[i])
        {
            result.emplace_back(
                nullptr,
                EC_POINT_free);
            continue;
        }

        result.emplace_back(
            PointMul(
                ecc,
                points[i],
                scalars[i].get()));
    }

    return result;
}

/*-------------------------------------------------------------
    SumGeneratorMul
--------------------------------------------------------------*/

ECPoint_ptr
SumGeneratorMul(
        const ECCContext& ecc,
        const std::vector<BN_ptr>& scalars)
{
    auto points =
        MultiGeneratorMul(
            ecc,
            scalars);

    std::vector<const EC_POINT*> list;

    list.reserve(points.size());

    for(const auto& P : points)
    {
        if(P)
            list.push_back(P.get());
    }

    return MultiPointAdd(
            ecc,
            list);
}

/*-------------------------------------------------------------
    ScalarVectorAdd
--------------------------------------------------------------*/

BN_ptr
ScalarVectorAdd(
        const ECCContext& ecc,
        const std::vector<BN_ptr>& scalars)
{
    BN_ptr result(
        BN_new(),
        BN_free);

    if(!result)
    {
        return BN_ptr(
            nullptr,
            BN_free);
    }

    BN_zero(result.get());

    for(const auto& x : scalars)
    {
        if(!x)
            continue;

        BN_mod_add(
            result.get(),
            result.get(),
            x.get(),
            ecc.Order(),
            ecc.Context());
    }

    return result;
}

} // namespace BE