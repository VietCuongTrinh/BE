#ifndef MTBE_H
#define MTBE_H

#include "params.h"

#include <vector>
#include <string>

using namespace std;

/*============================================================
  Setup / System Initialization
============================================================*/

bool Setup(
    PublicParams &pp,
    MasterKey &msk,
    int maxUsers,
    int maxGroups,
    int maxGroupSize
);


/*============================================================
  Key Generation
============================================================*/

bool KeyGen(
    const PublicParams &pp,
    const MasterKey &msk,
    const UserIdentity &id,
    SecretKey &sk
);


/*============================================================
  Encryption
============================================================*/

bool Encrypt(
    const PublicParams &pp,
    const EncryptionPolicy &policy,
    CipherHeader &hdr,
    vector<SessionKey> &sessionKeys
);


/*============================================================
  Partial Decryption
============================================================*/

bool Decrypt(
    const PublicParams &pp,
    const CipherHeader &hdr,
    const SecretKey &sk,
    int groupID,
    PartialKey &partialKey
);


/*============================================================
  Recover Session Key
============================================================*/

bool Recover(
    const PublicParams &pp,
    const vector<PartialKey> &partialKeys,
    int threshold,
    SessionKey &sessionKey
);


/*============================================================
  Polynomial Functions
============================================================*/

bool GeneratePolynomial(
    Polynomial &poly,
    int degree
);

bool EvaluatePolynomial(
    const Polynomial &poly,
    const bn_t x,
    bn_t result
);

bool LagrangeCoefficient(
    const vector<bn_t> &x,
    int index,
    bn_t coeff
);


/*============================================================
  Hash Functions
============================================================*/

bool HashToZp(
    const string &identity,
    bn_t result
);


/*============================================================
  Dummy Users
============================================================*/

bool GenerateDummyUsers(
    vector<UserIdentity> &dummyUsers,
    int numberOfGroups,
    int numberOfDummyUsers
);


/*============================================================
  Pairing Utilities
============================================================*/

bool Pairing(
    const g1_t P,
    const g2_t Q,
    gt_t result
);

bool GTExponent(
    const gt_t input,
    const bn_t exponent,
    gt_t output
);


/*============================================================
  Group Operations
============================================================*/

bool RandomScalar(
    bn_t value
);

bool RandomG1(
    g1_t P
);

bool RandomG2(
    g2_t P
);


/*============================================================
  Secret Key Utilities
============================================================*/

bool ComputeSecretKey(
    const bn_t alpha,
    const bn_t hashValue,
    const bn_t polyValue,
    g1_t sk
);


/*============================================================
  Encryption Utilities
============================================================*/

bool ComputeC1(
    const PublicParams &pp,
    const bn_t s,
    g1_t C1
);

bool ComputeC2(
    const PublicParams &pp,
    const EncryptionPolicy &policy,
    const bn_t s,
    g2_t C2
);


/*============================================================
  Partial Key Utilities
============================================================*/

bool ComputePartialKey(
    const PublicParams &pp,
    const CipherHeader &hdr,
    const SecretKey &sk,
    int groupID,
    gt_t partial
);


/*============================================================
  Recover Utilities
============================================================*/

bool RecoverSessionKey(
    const vector<PartialKey> &partialKeys,
    const vector<bn_t> &lagrangeCoeff,
    gt_t session
);


/*============================================================
  Printing
============================================================*/

void PrintBN(const bn_t value);

void PrintG1(const g1_t value);

void PrintG2(const g2_t value);

void PrintGT(const gt_t value);


/*============================================================
  Serialization
============================================================*/

bool SavePublicParams(
    const PublicParams &pp,
    const string &filename
);

bool LoadPublicParams(
    PublicParams &pp,
    const string &filename
);

bool SaveSecretKey(
    const SecretKey &sk,
    const string &filename
);

bool LoadSecretKey(
    SecretKey &sk,
    const string &filename
);


/*============================================================
  Benchmark
============================================================*/

double GetCurrentTime();

void StartTimer();

double StopTimer();


#endif