/******************************************************************************
*
*   setup.cpp
*
*   Identity-based Multi-group Threshold Broadcast Encryption
*   RELIC Toolkit + BLS12-381
*
******************************************************************************/

#include "mtbe.h"

#include <iostream>
#include <stdexcept>

using namespace std;


/******************************************************************************
*
* Initialize RELIC
*
******************************************************************************/

bool InitializeRelic()
{
    if (core_init() != RLC_OK)
    {
        core_clean();
        return false;
    }

    if (pc_param_set_any() != RLC_OK)
    {
        core_clean();
        return false;
    }

    return true;
}


/******************************************************************************
*
* Clean RELIC
*
******************************************************************************/

void CleanRelic()
{
    core_clean();
}


/******************************************************************************
*
* Generate random scalar
*
******************************************************************************/

bool RandomScalar(bn_t value)
{
    bn_t order;

    bn_null(order);

    bn_new(order);

    g1_get_ord(order);

    bn_rand_mod(value, order);

    bn_free(order);

    return true;
}


/******************************************************************************
*
* Generate random G1 point
*
******************************************************************************/

bool RandomG1(g1_t P)
{
    bn_t k;

    bn_null(k);

    bn_new(k);

    RandomScalar(k);

    g1_mul_gen(P, k);

    bn_free(k);

    return true;
}


/******************************************************************************
*
* Generate random G2 point
*
******************************************************************************/

bool RandomG2(g2_t P)
{
    bn_t k;

    bn_null(k);

    bn_new(k);

    RandomScalar(k);

    g2_mul_gen(P, k);

    bn_free(k);

    return true;
}


/******************************************************************************
*
* Compute pairing
*
******************************************************************************/

bool Pairing(
    const g1_t P,
    const g2_t Q,
    gt_t result)
{
    pc_map(result, P, Q);

    return true;
}


/******************************************************************************
*
* GT exponentiation
*
******************************************************************************/

bool GTExponent(
    const gt_t input,
    const bn_t exponent,
    gt_t output)
{
    gt_exp(output, input, exponent);

    return true;
}


/******************************************************************************
*
* Initialize Public Parameters
*
******************************************************************************/

static void InitializePublicParameters(
        PublicParams &pp)
{
    g1_null(pp.g);
    g1_new(pp.g);

    g2_null(pp.g_tilde);
    g2_new(pp.g_tilde);

    gt_null(pp.egg);
    gt_new(pp.egg);

    g1_null(pp.g_alpha);
    g1_new(pp.g_alpha);

    pp.alphaPower.clear();

    pp.eggP0.clear();

    pp.dummySecretKeys.clear();
}


/******************************************************************************
*
* Initialize Master Key
*
******************************************************************************/

static void InitializeMasterKey(
        MasterKey &msk)
{
    bn_null(msk.alpha);

    bn_new(msk.alpha);

    msk.polys.clear();
}


/******************************************************************************
*
* Generate generators
*
******************************************************************************/

static void GenerateGenerators(
        PublicParams &pp)
{
    g1_get_gen(pp.g);

    g2_get_gen(pp.g_tilde);

    pc_map(pp.egg,
           pp.g,
           pp.g_tilde);
}


/******************************************************************************
*
* Generate alpha
*
******************************************************************************/

static void GenerateMasterSecret(
        MasterKey &msk,
        PublicParams &pp)
{
    RandomScalar(msk.alpha);

    g1_mul(pp.g_alpha,
           pp.g,
           msk.alpha);
}


/******************************************************************************
*
* Allocate alpha powers
*
******************************************************************************/

static void AllocateAlphaTable(
        PublicParams &pp,
        int tableSize)
{
    pp.alphaPower.resize(tableSize);

    for(int i=0;i<tableSize;i++)
    {
        g2_null(pp.alphaPower[i]);
        g2_new(pp.alphaPower[i]);
    }
}


/******************************************************************************
*
* Allocate e(g,g)^P(0)
*
******************************************************************************/

static void AllocateSessionTable(
        PublicParams &pp,
        int groups)
{
    pp.eggP0.resize(groups);

    for(int i=0;i<groups;i++)
    {
        gt_null(pp.eggP0[i]);
        gt_new(pp.eggP0[i]);
    }
}


/******************************************************************************
*
* Allocate dummy secret keys
*
******************************************************************************/

static void AllocateDummyKeys(
        PublicParams &pp,
        int number)
{
    pp.dummySecretKeys.resize(number);

    for(int i=0;i<number;i++)
    {
        g1_null(pp.dummySecretKeys[i]);
        g1_new(pp.dummySecretKeys[i]);
    }
}
/******************************************************************************
*
* Setup Algorithm (Part 2)
*
******************************************************************************/

bool Setup(
        PublicParams &pp,
        MasterKey &msk,
        int maxUsers,
        int maxGroups,
        int maxGroupSize)
{
    if(!InitializeRelic())
        return false;

    InitializePublicParameters(pp);

    InitializeMasterKey(msk);

    GenerateGenerators(pp);

    GenerateMasterSecret(msk, pp);

    /*
     * allocate memory
     */

    int alphaTableSize =
            2 * maxGroups * maxGroupSize + 1;

    AllocateAlphaTable(pp, alphaTableSize);

    AllocateSessionTable(pp, maxGroups);

    AllocateDummyKeys(pp, maxGroupSize - 1);

    /*
     * Generate m random polynomials
     */

    msk.polys.resize(maxGroups);

    for(int j = 0; j < maxGroups; j++)
    {
        GeneratePolynomial(
                msk.polys[j],
                maxGroupSize - 1);
    }

    /*
     * Compute
     *
     *      e(g,g2)^Pj(0)
     */

    for(int j = 0; j < maxGroups; j++)
    {
        bn_t constant;

        bn_null(constant);

        bn_new(constant);

        bn_copy(
                constant,
                msk.polys[j].coef[0]);

        gt_exp(
                pp.eggP0[j],
                pp.egg,
                constant);

        bn_free(constant);
    }

    /*
     * alpha^0 = 1
     */

    bn_t order;

    bn_t alphaPower;

    bn_null(order);
    bn_null(alphaPower);

    bn_new(order);
    bn_new(alphaPower);

    g1_get_ord(order);

    bn_set_dig(alphaPower, 1);

    /*
     * Compute
     *
     * g2^(alpha^i)
     */

    for(int i = 0; i < alphaTableSize; i++)
    {
        g2_mul_gen(
                pp.alphaPower[i],
                alphaPower);

        bn_mul(
                alphaPower,
                alphaPower,
                msk.alpha);

        bn_mod(
                alphaPower,
                alphaPower,
                order);
    }

    bn_free(order);

    bn_free(alphaPower);

    /*
     * Continue in Part 3
     */

    return true;
}
