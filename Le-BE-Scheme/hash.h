#ifndef HASH_H
#define HASH_H

#include <string>

#include <relic/relic.h>

/**
 * Hash a string into Zp
 *
 * @param identity input identity
 * @param result output scalar in Zp
 * @return true if success
 */
bool HashToZp(
        const std::string &identity,
        bn_t result);


/**
 * Convert byte array into Zp
 */
bool BytesToZp(
        const uint8_t *buffer,
        int length,
        bn_t result);


/**
 * SHA256
 */
bool SHA256Hash(
        const std::string &input,
        uint8_t output[32]);

#endif