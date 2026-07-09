/********************************************************************
*
* setup.cpp
*
* System Setup
*
********************************************************************/

#include "be.h"

namespace BE
{

/*==============================================================
    Constructor
==============================================================*/

BroadcastEncryption::BroadcastEncryption()
{
}

/*-------------------------------------------------------------*/

BroadcastEncryption::~BroadcastEncryption()
{
}

/*==============================================================
    Setup
==============================================================*/

bool BroadcastEncryption::Setup()
{
    //----------------------------------------------------------
    // Initialize ECC Context
    //----------------------------------------------------------

    params_.ecc =
        std::make_shared<ECCContext>();

    if(!params_.ecc)
        return false;

    if(!params_.ecc->Initialize())
        return false;

    //----------------------------------------------------------
    // Generator
    //----------------------------------------------------------

    params_.G =
        CopyPoint(
            *params_.ecc,
            params_.ecc->Generator());

    if(!params_.G)
        return false;

    //----------------------------------------------------------
    // Group Order
    //----------------------------------------------------------

    params_.order =
        CopyScalar(
            params_.ecc->Order());

    if(!params_.order)
        return false;

    //----------------------------------------------------------
    // Create LSS Generator
    //----------------------------------------------------------

    lss_ =
        std::make_unique<LSSGenerator>(
            *params_.ecc);

    if(!lss_)
        return false;

    //----------------------------------------------------------
    // Clear Public Key Directory
    //----------------------------------------------------------

    params_.directory.clear();

    return true;
}

/*==============================================================
    Public Parameters
==============================================================*/

const PublicParameters&
BroadcastEncryption::GetPublicParameters() const
{
    return params_;
}

/*==============================================================
    Build LSS Matrix
==============================================================*/

bool BroadcastEncryption::BuildLSSMatrix(
        const std::string& policy,
        LSSMatrix& matrix)
{
    if(!lss_)
        return false;

    return lss_->Generate(
                policy,
                matrix);
}

} // namespace BE