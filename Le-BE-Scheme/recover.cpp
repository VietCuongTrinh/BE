/******************************************************************************
*
* recover.cpp
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
* Recover session key from partial keys
*
******************************************************************************/

bool RecoverSessionKey(
        const vector<PartialKey> &partialKeys,
        const vector<bn_t> &lagrangeCoeff,
        gt_t session)
{
    if(partialKeys.empty())
        return false;

    gt_set_unity(session);

    for(size_t i = 0; i < partialKeys.size(); i++)
    {
        gt_t temp;

        gt_null(temp);
        gt_new(temp);

        gt_exp(
            temp,
            partialKeys[i].value,
            lagrangeCoeff[i]);

        gt_mul(
            session,
            session,
            temp);

        gt_free(temp);
    }

    return true;
}


/******************************************************************************
*
* Recover
*
******************************************************************************/

bool Recover(
        const PublicParams &pp,
        const vector<PartialKey> &partialKeys,
        int threshold,
        SessionKey &sessionKey)
{
    (void)pp;

    if(partialKeys.size() < (size_t)threshold)
        return false;

    vector<bn_t> xValues(threshold);

    for(int i = 0; i < threshold; i++)
    {
        bn_null(xValues[i]);
        bn_new(xValues[i]);

        /*
            In this implementation we simply use

                    x = uid

            as interpolation point.
        */

        bn_set_dig(
            xValues[i],
            partialKeys[i].uid);
    }

    vector<bn_t> coeff(threshold);

    for(int i = 0; i < threshold; i++)
    {
        bn_null(coeff[i]);
        bn_new(coeff[i]);

        if(!LagrangeCoefficient(
                    xValues,
                    i,
                    coeff[i]))
        {
            return false;
        }
    }

    gt_null(sessionKey.value);
    gt_new(sessionKey.value);

    if(!RecoverSessionKey(
                partialKeys,
                coeff,
                sessionKey.value))
    {
        return false;
    }

    /*
        Release memory
    */

    for(int i = 0; i < threshold; i++)
    {
        bn_free(xValues[i]);
        bn_free(coeff[i]);
    }

    return true;
}