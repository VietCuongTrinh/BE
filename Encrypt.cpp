/********************************************************************
*
* encrypt.cpp
*
* Broadcast Encryption
*
********************************************************************/

#include "be.h"

namespace BE
{

/*==============================================================
    Encrypt
==============================================================*/

bool BroadcastEncryption::Encrypt(
        const std::string& policy,
        Header& header)
{
    //----------------------------------------------------------
    // Check system
    //----------------------------------------------------------

    if(params_.ecc == nullptr)
        return false;

    //----------------------------------------------------------
    // Build LSS Matrix
    //----------------------------------------------------------

    if(!BuildLSSMatrix(policy, header.matrix))
        return false;

    //----------------------------------------------------------
    // Generate random secret s
    //----------------------------------------------------------

    BN_ptr s =
        RandomNonZeroScalar(
            *params_.ecc);

    if(!s)
        return false;

    //----------------------------------------------------------
    // Session Key
    //
    //      K = g^s
    //----------------------------------------------------------

    SessionKey session;

    session.K =
        GeneratorMul(
            *params_.ecc,
            s.get());

    if(!session.K)
        return false;

    //----------------------------------------------------------
    // Compute λ
    //----------------------------------------------------------

    std::vector<BN_ptr> lambda;

    if(!GenerateShares(
            *params_.ecc,
            header.matrix,
            s.get(),
            lambda))
    {
        return false;
    }

    //----------------------------------------------------------
    // Ciphertext Components
    //----------------------------------------------------------

    header.C.clear();

    for(size_t i = 0;
        i < header.matrix.Rows();
        ++i)
    {
        //------------------------------------------------------
        // User ID
        //------------------------------------------------------

        uint32_t uid =
            std::stoul(
                header.matrix.rho[i]);

        //------------------------------------------------------
        // Lookup public key
        //------------------------------------------------------

        auto it =
            params_.directory.find(uid);

        if(it == params_.directory.end())
            return false;

        //------------------------------------------------------
        // PK = g^{a_u}
        //------------------------------------------------------

        const EC_POINT* pk =
            it->second.pk.get();

        //------------------------------------------------------
        // Ci = PK^{λ_i}
        //------------------------------------------------------

        auto Ci =
            PointMul(
                *params_.ecc,
                pk,
                lambda[i].get());

        if(!Ci)
            return false;

        header.C.push_back(
            std::move(Ci));
    }

    //----------------------------------------------------------
    // Save Policy
    //----------------------------------------------------------

    header.policy = policy;

    //----------------------------------------------------------
    // Save Target Directory
    //----------------------------------------------------------

    header.directory =
        params_.directory;

    return true;
}

}