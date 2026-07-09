/********************************************************************
*
* partial_decrypt.cpp
*
* Partial Decryption
*
********************************************************************/

#include "be.h"

namespace BE
{

/*==============================================================
    Partial Decryption
==============================================================*/

bool BroadcastEncryption::PartialDecrypt(
        const Header& header,
        const User& user,
        PartialKey& partial)
{
    //----------------------------------------------------------
    // Check
    //----------------------------------------------------------

    if(params_.ecc == nullptr)
        return false;

    if(!user.sk)
        return false;

    //----------------------------------------------------------
    // Parse policy
    //----------------------------------------------------------

    std::shared_ptr<AccessNode> root;

    if(!ParsePolicy(
            header.policy,
            root))
    {
        return false;
    }

    //----------------------------------------------------------
    // User attributes
    //----------------------------------------------------------

    std::vector<std::string> attrs;

    attrs.push_back(
        std::to_string(user.id));

    //----------------------------------------------------------
    // Policy satisfied?
    //----------------------------------------------------------

    std::vector<int> rows;

    if(!FindMinimalSatisfiedRows(
            root,
            attrs,
            rows))
    {
        return false;
    }

    //----------------------------------------------------------
    // Reconstruction coefficients
    //----------------------------------------------------------

    std::vector<BN_ptr> beta;

    if(!ReconstructionCoefficients(
            *params_.ecc,
            header.matrix,
            rows,
            beta))
    {
        return false;
    }

    //----------------------------------------------------------
    // Find my row
    //----------------------------------------------------------

    int index = -1;

    for(size_t i = 0; i < rows.size(); ++i)
    {
        if(header.matrix.rho[rows[i]]
                == std::to_string(user.id))
        {
            index = static_cast<int>(i);
            break;
        }
    }

    if(index < 0)
        return false;

    //----------------------------------------------------------
    // exponent = β_i / a_u
    //----------------------------------------------------------

    auto inv =
        ScalarInverse(
            *params_.ecc,
            user.sk.get());

    auto exponent =
        ScalarMul(
            *params_.ecc,
            beta[index].get(),
            inv.get());

    //----------------------------------------------------------
    // D = C_i^(β_i/a_u)
    //----------------------------------------------------------

    partial.id = user.id;

    partial.D =
        PointMul(
            *params_.ecc,
            header.C[
                rows[index]
            ].get(),
            exponent.get());

    return partial.D != nullptr;
}

/*==============================================================
    Verify Partial Key
==============================================================*/

bool BroadcastEncryption::VerifyPartialKey(
        const PartialKey& partial) const
{
    if(params_.ecc == nullptr)
        return false;

    if(!partial.D)
        return false;

    return CheckPoint(
            *params_.ecc,
            partial.D.get());
}

}