/******************************************************************************
*
* main.cpp
*
* Demo program
*
******************************************************************************/

#include "mtbe.h"

#include <iostream>

using namespace std;

int main()
{
    cout << "==========================================" << endl;
    cout << " Identity-based MTBE using RELIC Toolkit" << endl;
    cout << "==========================================" << endl;

    PublicParams pp;
    MasterKey msk;

    if(!Setup(pp,
              msk,
              MAX_USERS,
              MAX_GROUPS,
              MAX_GROUP_SIZE))
    {
        cout << "Setup failed." << endl;
        return -1;
    }

    cout << "System setup completed." << endl;

    /*************************************************
     *
     * Create one user
     *
     *************************************************/

    UserIdentity alice;

    alice.uid = 1;

    alice.groupID.resize(MAX_GROUPS);

    alice.groupID[0] = "alice@group1";

    alice.groupID[1] = "alice@group2";

    SecretKey aliceSK;

    if(!KeyGen(pp,
               msk,
               alice,
               aliceSK))
    {
        cout << "Key generation failed." << endl;
        return -1;
    }

    cout << "KeyGen completed." << endl;

    /*************************************************
     *
     * Encryption policy
     *
     *************************************************/

    EncryptionPolicy policy;

    TargetGroup g1;

    g1.gid = 0;

    g1.threshold = 2;

    g1.users.push_back(1);

    g1.users.push_back(2);

    g1.users.push_back(3);

    policy.groups.push_back(g1);

    CipherHeader hdr;

    vector<SessionKey> sessionKeys;

    if(!Encrypt(pp,
                policy,
                hdr,
                sessionKeys))
    {
        cout << "Encryption failed." << endl;
        return -1;
    }

    cout << "Encryption completed." << endl;

    /*************************************************
     *
     * Partial decryption
     *
     *************************************************/

    PartialKey pk;

    if(!Decrypt(pp,
                hdr,
                aliceSK,
                0,
                pk))
    {
        cout << "Decrypt failed." << endl;
        return -1;
    }

    cout << "Partial decryption completed." << endl;

    vector<PartialKey> partials;

    partials.push_back(pk);

    SessionKey recovered;

    if(!Recover(pp,
                partials,
                1,
                recovered))
    {
        cout << "Recover failed." << endl;
        return -1;
    }

    cout << "Recover completed." << endl;

    cout << endl;

    cout << "Demo finished successfully." << endl;

    CleanRelic();

    return 0;
}