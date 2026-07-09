/******************************************************************************
*
* hash.cpp
*
* Original implementation
* RELIC Toolkit
*
******************************************************************************/

#include "hash.h"

#include <cstring>

using namespace std;


/******************************************************************************
*
* SHA256
*
******************************************************************************/

bool SHA256Hash(
        const string &input,
        uint8_t output[32])
{
    md_map_sh256(
            output,
            (const uint8_t*)input.data(),
            input.size());

    return true;
}


/******************************************************************************
*
* Convert bytes -> Zp
*
******************************************************************************/

bool BytesToZp(
        const uint8_t *buffer,
        int length,
        bn_t result)
{
    bn_t order;

    bn_null(order);
    bn_new(order);

    g1_get_ord(order);

    bn_read_bin(
            result,
            buffer,
            length);

    bn_mod(
            result,
            result,
            order);

    bn_free(order);

    return true;
}


/******************************************************************************
*
* Hash identity into Zp
*
******************************************************************************/

bool HashToZp(
        const string &identity,
        bn_t result)
{
    uint8_t digest[32];

    SHA256Hash(
            identity,
            digest);

    BytesToZp(
            digest,
            32,
            result);

    return true;
}