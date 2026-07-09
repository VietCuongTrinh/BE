#ifndef BE_BE_H
#define BE_BE_H

/********************************************************************
*
*   be.h
*
*   Broadcast Encryption based on ECC
*
********************************************************************/

#include "config.h"
#include "types.h"
#include "ecc.h"
#include "util.h"
#include "lss.h"

#include <memory>
#include <vector>
#include <string>

namespace BE
{

/*==============================================================
    Broadcast Encryption
==============================================================*/

class BroadcastEncryption
{
public:

    BroadcastEncryption();

    ~BroadcastEncryption();

    /*----------------------------------------------------------
        Setup
    ----------------------------------------------------------*/

    bool Setup();

    /*----------------------------------------------------------
        Key Generation
    ----------------------------------------------------------*/

    bool KeyGen(
            User& user);

    /*----------------------------------------------------------
        Encryption
    ----------------------------------------------------------*/

    bool Encrypt(
            const std::string& policy,
            const std::vector<User>& users,
            Header& header);

    /*----------------------------------------------------------
        Partial Decryption
    ----------------------------------------------------------*/

    bool PartialDecrypt(
            const Header& header,
            const User& user,
            PartialKey& partialKey);

    /*----------------------------------------------------------
        Collaborative Decryption
    ----------------------------------------------------------*/

    bool CollaborativeDecrypt(
            const Header& header,
            const std::vector<PartialKey>& partialKeys,
            SessionKey& sessionKey);

    /*----------------------------------------------------------
        Public Parameters
    ----------------------------------------------------------*/

    const PublicParameters&
    GetPublicParameters() const;

    /*----------------------------------------------------------
        LSS Matrix
    ----------------------------------------------------------*/

    bool BuildLSSMatrix(
            const std::string& policy,
            LSSMatrix& matrix);

    /*----------------------------------------------------------
        Save / Load
    ----------------------------------------------------------*/

    bool SavePublicParameters(
            const std::string& filename) const;

    bool LoadPublicParameters(
            const std::string& filename);

    bool SaveHeader(
            const Header& header,
            const std::string& filename) const;

    bool LoadHeader(
            const std::string& filename,
            Header& header);

private:

    /*==========================================================
        System Parameters
    ==========================================================*/

    PublicParameters params_;

    std::unique_ptr<LSSGenerator> lss_;

    /*==========================================================
        Internal Algorithms
    ==========================================================*/

    bool GenerateHeader(
            const LSSMatrix& matrix,
            const std::vector<User>& users,
            Header& header);

    bool ComputeCipherComponents(
            const LSSMatrix& matrix,
            const std::vector<User>& users,
            const std::vector<BN_ptr>& lambda,
            Header& header);

    bool VerifyHeader(
            const Header& header) const;

    bool VerifyUser(
            const User& user) const;

    bool VerifyPartialKey(
            const PartialKey& partialKey) const;

    /*==========================================================
        Serialization Helpers
    ==========================================================*/

    bool SerializeHeader(
            const Header& header,
            std::string& output) const;

    bool DeserializeHeader(
            const std::string& input,
            Header& header);

    bool SerializeParameters(
            std::string& output) const;

    bool DeserializeParameters(
            const std::string& input);

};

/*==============================================================
    Helper Functions
==============================================================*/

bool VerifyPolicy(
        const std::string& policy);

bool VerifyUserList(
        const std::vector<User>& users);

bool VerifyPartialKeyList(
        const std::vector<PartialKey>& partialKeys);

} // namespace BE

#endif