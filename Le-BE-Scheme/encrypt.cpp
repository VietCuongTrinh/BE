/******************************************************************************
*
* encrypt.cpp
*
* Original MTBE implementation
* RELIC Toolkit + BLS12-381
*
******************************************************************************/

#include "mtbe.h"

#include <iostream>

using namespace std;


/******************************************************************************
*
* Compute C1 = g^r
*
******************************************************************************/

bool ComputeC1(
        const PublicParams &pp,
        const bn_t r,
        g1_t C1)
{
    g1_mul(C1, pp.g, r);
    return true;
}


/******************************************************************************
*
* Compute C2 = g2^r
*
******************************************************************************/

bool ComputeC2(
        const PublicParams &pp,
        const bn_t r,
        g2_t C2)
{
    g2_mul(C2, pp.g_tilde, r);
    return true;
}


/******************************************************************************
*
* Derive one session key
*
******************************************************************************/

static bool DeriveSessionKey(
        const PublicParams &pp,
        const bn_t r,
        int groupIndex,
        SessionKey &key)
{
    gt_null(key.value);
    gt_new(key.value);

    gt_exp(key.value,
           pp.eggP0[groupIndex],
           r);

    return true;
}


/******************************************************************************
*
* Encrypt
*
******************************************************************************/

bool Encrypt(
        const PublicParams &pp,
        const EncryptionPolicy &policy,
        CipherHeader &hdr,
        vector<SessionKey> &sessionKeys)
{
    bn_t r;

    bn_null(r);
    bn_new(r);

    if (!RandomScalar(r))
    {
        bn_free(r);
        return false;
    }

    /***************************
        Header
    ****************************/

    g1_null(hdr.C1);
    g1_new(hdr.C1);

    g2_null(hdr.C2);
    g2_new(hdr.C2);

    ComputeC1(pp, r, hdr.C1);

    ComputeC2(pp, r, hdr.C2);

    /***************************
        Copy policy
    ****************************/

    hdr.targetSets.clear();
    hdr.thresholds.clear();

    sessionKeys.clear();

    for (const auto &grp : policy.groups)
    {
        hdr.targetSets.push_back(grp.users);

        hdr.thresholds.push_back(grp.threshold);

        SessionKey sk;

        DeriveSessionKey(
                pp,
                r,
                grp.gid,
                sk);

        sessionKeys.push_back(sk);
    }

    bn_free(r);

    return true;
}