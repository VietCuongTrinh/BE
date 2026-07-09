/********************************************************************
*
* keygen.cpp
*
* Key Generation
*
********************************************************************/

#include "be.h"

namespace BE
{

/*==============================================================
    Key Generation
==============================================================*/

bool BroadcastEncryption::KeyGen(
        User& user)
{
    //----------------------------------------------------------
    // System initialized?
    //----------------------------------------------------------

    if(params_.ecc == nullptr)
        return false;

    //----------------------------------------------------------
    // Generate secret key
    //
    //      a_u ∈ Zq*
    //----------------------------------------------------------

    user.sk =
        RandomNonZeroScalar(
            *params_.ecc);

    if(!user.sk)
        return false;

    //----------------------------------------------------------
    // Public key
    //
    //      PK = g^{a_u}
    //----------------------------------------------------------

    user.pk =
        GeneratorMul(
            *params_.ecc,
            user.sk.get());

    if(!user.pk)
        return false;

    //----------------------------------------------------------
    // Verify
    //----------------------------------------------------------

    if(!CheckScalar(
            *params_.ecc,
            user.sk.get()))
        return false;

    if(!CheckPoint(
            *params_.ecc,
            user.pk.get()))
        return false;

    //----------------------------------------------------------
    // Update public directory
    //----------------------------------------------------------

    PublicKey entry;

    entry.id = user.id;

    entry.name = user.name;

    entry.pk =
        CopyPoint(
            *params_.ecc,
            user.pk.get());

    params_.directory[user.id] =
        std::move(entry);

    return true;
}

/*==============================================================
    Verify User
==============================================================*/

bool BroadcastEncryption::VerifyUser(
        const User& user) const
{
    if(params_.ecc == nullptr)
        return false;

    if(!user.sk)
        return false;

    if(!user.pk)
        return false;

    auto expected =
        GeneratorMul(
            *params_.ecc,
            user.sk.get());

    return PointEqual(
            *params_.ecc,
            expected.get(),
            user.pk.get());
}

} // namespace BE