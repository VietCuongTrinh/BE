/********************************************************************
*
* collaborative_decrypt.cpp
*
* Collaborative Decryption
*
********************************************************************/

#include "be.h"

namespace BE
{

/*==============================================================
    Collaborative Decryption
==============================================================*/

bool BroadcastEncryption::CollaborativeDecrypt(
        const Header& header,
        const std::vector<PartialKey>& partialKeys,
        SessionKey& session)
{
    //----------------------------------------------------------
    // Check
    //----------------------------------------------------------

    if(params_.ecc == nullptr)
        return false;

    if(partialKeys.empty())
        return false;

    //----------------------------------------------------------
    // Initialize
    //----------------------------------------------------------

    auto result =
        PointInfinity(*params_.ecc);

    if(!result)
        return false;

    //----------------------------------------------------------
    // Aggregate all partial decryptions
    //----------------------------------------------------------

    for(const auto& key : partialKeys)
    {
        if(!key.D)
            return false;

        result =
            PointAdd(
                *params_.ecc,
                result.get(),
                key.D.get());

        if(!result)
            return false;
    }

    //----------------------------------------------------------
    // Output session key
    //----------------------------------------------------------

    session.K =
        std::move(result);

    return true;
}

/*==============================================================
    Verify Partial Keys
==============================================================*/

bool BroadcastEncryption::VerifyPartialKeyList(
        const std::vector<PartialKey>& partialKeys)
{
    if(params_.ecc == nullptr)
        return false;

    for(const auto& key : partialKeys)
    {
        if(!key.D)
            return false;

        if(!CheckPoint(
                *params_.ecc,
                key.D.get()))
        {
            return false;
        }
    }

    return true;
}

} // namespace BE