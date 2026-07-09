/******************************************************************************
*
* keygen.cpp
*
* Identity-based Multi-group Threshold Broadcast Encryption
* RELIC Toolkit + BLS12-381
*
******************************************************************************/

#include "mtbe.h"

#include <iostream>

using namespace std;


/******************************************************************************
*
* Compute
*
*      sk = g^(poly/(alpha+H(ID)))
*
******************************************************************************/

bool ComputeSecretKey(
        const bn_t alpha,
        const bn_t hashValue,
        const bn_t polyValue,
        g1_t sk)
{
    bn_t order;
    bn_t denominator;
    bn_t inverse;
    bn_t exponent;

    bn_null(order);
    bn_null(denominator);
    bn_null(inverse);
    bn_null(exponent);

    bn_new(order);
    bn_new(denominator);
    bn_new(inverse);
    bn_new(exponent);

    g1_get_ord(order);

    /* denominator = alpha + H(ID) */

    bn_add(denominator, alpha, hashValue);
    bn_mod(denominator, denominator, order);

    /* inverse denominator */

    if (bn_is_zero(denominator))
    {
        bn_free(order);
        bn_free(denominator);
        bn_free(inverse);
        bn_free(exponent);
        return false;
    }

    bn_mod_inv(inverse, denominator, order);

    /* exponent = polyValue / (alpha+H(ID)) */

    bn_mul(exponent, polyValue, inverse);
    bn_mod(exponent, exponent, order);

    /* sk = g^exponent */

    g1_mul_gen(sk, exponent);

    bn_free(order);
    bn_free(denominator);
    bn_free(inverse);
    bn_free(exponent);

    return true;
}


/******************************************************************************
*
* Key Generation
*
******************************************************************************/

bool KeyGen(
        const PublicParams &pp,
        const MasterKey &msk,
        const UserIdentity &id,
        SecretKey &sk)
{
    sk.uid = id.uid;

    sk.sk.resize(id.groupID.size());

    for (size_t j = 0; j < id.groupID.size(); j++)
    {
        g1_null(sk.sk[j]);
        g1_new(sk.sk[j]);

        /* Empty identity -> user not in this group */

        if (id.groupID[j].empty())
        {
            g1_set_infty(sk.sk[j]);
            continue;
        }

        bn_t hashValue;
        bn_t polyValue;

        bn_null(hashValue);
        bn_null(polyValue);

        bn_new(hashValue);
        bn_new(polyValue);

        /* Hash identity to Zp */

        if (!HashToZp(id.groupID[j], hashValue))
        {
            bn_free(hashValue);
            bn_free(polyValue);
            return false;
        }

        /* Evaluate polynomial */

        if (!EvaluatePolynomial(
                    msk.polys[j],
                    hashValue,
                    polyValue))
        {
            bn_free(hashValue);
            bn_free(polyValue);
            return false;
        }

        /* Compute secret key */

        if (!ComputeSecretKey(
                    msk.alpha,
                    hashValue,
                    polyValue,
                    sk.sk[j]))
        {
            bn_free(hashValue);
            bn_free(polyValue);
            return false;
        }

        bn_free(hashValue);
        bn_free(polyValue);
    }

    return true;
}