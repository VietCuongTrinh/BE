/******************************************************************************
*
* decrypt.cpp
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
* Compute Pairing(C1, g2)
*
******************************************************************************/

static bool ComputeFirstPairing(
        const PublicParams &pp,
        const CipherHeader &hdr,
        gt_t result)
{
    pc_map(result,
           hdr.C1,
           pp.g_tilde);

    return true;
}


/******************************************************************************
*
* Compute Pairing(SK, C2)
*
******************************************************************************/

static bool ComputeSecondPairing(
        const CipherHeader &hdr,
        const SecretKey &sk,
        int groupID,
        gt_t result)
{
    if(groupID >= (int)sk.sk.size())
        return false;

    pc_map(result,
           sk.sk[groupID],
           hdr.C2);

    return true;
}


/******************************************************************************
*
* Combine pairings
*
******************************************************************************/

static bool CombinePairings(
        const gt_t A,
        const gt_t B,
        gt_t output)
{
    gt_mul(output,
           A,
           B);

    return true;
}


/******************************************************************************
*
* Compute Partial Session Key
*
******************************************************************************/

bool ComputePartialKey(
        const PublicParams &pp,
        const CipherHeader &hdr,
        const SecretKey &sk,
        int groupID,
        gt_t partial)
{
    gt_t left;
    gt_t right;

    gt_null(left);
    gt_null(right);

    gt_new(left);
    gt_new(right);

    if(!ComputeFirstPairing(
                pp,
                hdr,
                left))
    {
        return false;
    }

    if(!ComputeSecondPairing(
                hdr,
                sk,
                groupID,
                right))
    {
        return false;
    }

    CombinePairings(
            left,
            right,
            partial);

    gt_free(left);
    gt_free(right);

    return true;
}


/******************************************************************************
*
* Decrypt
*
******************************************************************************/

bool Decrypt(
        const PublicParams &pp,
        const CipherHeader &hdr,
        const SecretKey &sk,
        int groupID,
        PartialKey &partialKey)
{
    partialKey.uid = sk.uid;

    partialKey.gid = groupID;

    gt_null(partialKey.value);
    gt_new(partialKey.value);

    if(!ComputePartialKey(
                pp,
                hdr,
                sk,
                groupID,
                partialKey.value))
    {
        return false;
    }

    return true;
}