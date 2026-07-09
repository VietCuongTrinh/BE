/********************************************************************
*
* encrypt.cpp
*
********************************************************************/

#include "be.h"

namespace BE
{

bool BroadcastEncryption::Encrypt(
        const std::string& policy,
        Header& hdr)
{
    //----------------------------------------------------------
    // Build LSS Matrix
    //----------------------------------------------------------

    if(!BuildLSSMatrix(policy, hdr.matrix))
        return false;

    //----------------------------------------------------------
    // Random secret s
    //----------------------------------------------------------

    BN_ptr s = RandomNonZeroScalar(*params_.ecc);

    //----------------------------------------------------------
    // Session key K = g^s
    //----------------------------------------------------------

    SessionKey session;

    session.K = GeneratorMul(
                    *params_.ecc,
                    s.get());

    //----------------------------------------------------------
    // Generate λ
    //----------------------------------------------------------

    std::vector<BN_ptr> lambda;

    if(!GenerateShares(
            *params_.ecc,
            hdr.matrix,
            s.get(),
            lambda))
    {
        return false;
    }

    //----------------------------------------------------------
    // Compute Ci
    //----------------------------------------------------------

    hdr.C.clear();

    for(size_t i=0;i<hdr.matrix.Rows();i++)
    {
        const std::string& userID =
                hdr.matrix.rho[i];

        uint32_t id =
            std::stoul(userID);

        auto it =
            params_.directory.find(id);

        if(it==params_.directory.end())
            return false;

        EC_POINT* pk =
            it->second.pk.get();

        auto Ci =
            PointMul(
                *params_.ecc,
                pk,
                lambda[i].get());

        hdr.C.push_back(
            std::move(Ci));
    }

    //----------------------------------------------------------
    // Save policy
    //----------------------------------------------------------

    hdr.policy = policy;

    return true;
}

}

bool BroadcastEncryption::PartialDecrypt(
        const Header& hdr,
        const User& user,
        PartialKey& partial)
{
    //----------------------------------------------------------
    // Find user's row in ρ
    //----------------------------------------------------------

    int row = -1;

    for(size_t i = 0; i < hdr.matrix.rho.size(); ++i)
    {
        if(std::stoul(hdr.matrix.rho[i]) == user.id)
        {
            row = static_cast<int>(i);
            break;
        }
    }

    if(row < 0)
        return false;

    //----------------------------------------------------------
    // Compute reconstruction coefficients β
    //----------------------------------------------------------

    std::vector<int> rows = { row };

    std::vector<BN_ptr> beta;

    if(!ReconstructionCoefficients(
            *params_.ecc,
            hdr.matrix,
            rows,
            beta))
    {
        return false;
    }

    //----------------------------------------------------------
    // Compute inverse secret key
    //----------------------------------------------------------

    auto inv =
        ScalarInverse(
            *params_.ecc,
            user.sk.get());

    //----------------------------------------------------------
    // exponent = β / a_u
    //----------------------------------------------------------

    auto exponent =
        ScalarMul(
            *params_.ecc,
            beta[0].get(),
            inv.get());

    //----------------------------------------------------------
    // D = Ci^(β/a_u)
    //----------------------------------------------------------

    partial.id = user.id;

    partial.D =
        PointMul(
            *params_.ecc,
            hdr.C[row].get(),
            exponent.get());

    return true;
}

}

bool BroadcastEncryption::CollaborativeDecrypt(
        const Header& hdr,
        const std::vector<PartialKey>& partials,
        SessionKey& session)
{
    //----------------------------------------------------------
    // Need at least one partial key
    //----------------------------------------------------------

    if(partials.empty())
        return false;

    //----------------------------------------------------------
    // K = Σ Di
    //
    // (Group operation on elliptic curve)
    //----------------------------------------------------------

    auto K =
        PointInfinity(*params_.ecc);

    for(const auto& p : partials)
    {
        K =
            PointAdd(
                *params_.ecc,
                K.get(),
                p.D.get());
    }

    //----------------------------------------------------------
    // Output session key
    //----------------------------------------------------------

    session.K = std::move(K);

    return true;
}

} // namespace BE