#ifndef MTBE_PARAMS_H
#define MTBE_PARAMS_H

#include <relic/relic.h>

#include <vector>
#include <string>
#include <map>

using namespace std;

/*------------------------------------------------------------
| Global Parameters
------------------------------------------------------------*/

constexpr int SECURITY_LEVEL = 128;

/* Maximum number of users in the whole system */
constexpr int MAX_USERS = 100;

/* Maximum number of groups */
constexpr int MAX_GROUPS = 10;

/* Maximum users in one target group */
constexpr int MAX_GROUP_SIZE = 50;

/* SHA256 output length */
constexpr int HASH_SIZE = 32;


/*------------------------------------------------------------
| User Identity
------------------------------------------------------------*/

struct UserIdentity
{
    int uid;

    std::vector<std::string> groupID;

    UserIdentity()
    {
        uid = 0;
    }
};


/*------------------------------------------------------------
| Polynomial
------------------------------------------------------------*/

struct Polynomial
{
    std::vector<bn_t> coef;
};


/*------------------------------------------------------------
| Public Parameters
------------------------------------------------------------*/

struct PublicParams
{
    /* generators */

    g1_t g;

    g2_t g_tilde;

    gt_t egg;


    /* g^alpha */

    g1_t g_alpha;


    /*
     * g2^(alpha^i)
     *
     * size = 2*n*m + 1
     */

    std::vector<g2_t> alphaPower;


    /*
     * e(g,g2)^Pj(0)
     */

    std::vector<gt_t> eggP0;


    /*
     * Dummy secret keys
     */

    std::vector<g1_t> dummySecretKeys;
};


/*------------------------------------------------------------
| Master Secret Key
------------------------------------------------------------*/

struct MasterKey
{
    bn_t alpha;

    std::vector<Polynomial> polys;
};


/*------------------------------------------------------------
| Secret Key
------------------------------------------------------------*/

struct SecretKey
{
    int uid;

    std::vector<g1_t> sk;
};


/*------------------------------------------------------------
| Ciphertext Header
------------------------------------------------------------*/

struct CipherHeader
{
    g1_t C1;

    g2_t C2;

    /*
     * Description of target groups
     */

    std::vector<std::vector<int>> targetSets;

    std::vector<int> thresholds;
};


/*------------------------------------------------------------
| Partial Session Key
------------------------------------------------------------*/

struct PartialKey
{
    int uid;

    int gid;

    gt_t value;
};


/*------------------------------------------------------------
| Session Key
------------------------------------------------------------*/

struct SessionKey
{
    gt_t value;
};


/*------------------------------------------------------------
| Group Description
------------------------------------------------------------*/

struct TargetGroup
{
    int gid;

    int threshold;

    std::vector<int> users;
};


/*------------------------------------------------------------
| Whole Encryption Input
------------------------------------------------------------*/

struct EncryptionPolicy
{
    std::vector<TargetGroup> groups;
};


/*------------------------------------------------------------
| RELIC Initialization
------------------------------------------------------------*/

bool InitializeRelic();

void CleanRelic();


#endif