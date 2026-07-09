/********************************************************************
*
* main.cpp
*
* Demo Program
*
********************************************************************/

#include <iostream>
#include "be.h"

using namespace BE;

int main()
{
    std::cout << "========================================\n";
    std::cout << " Broadcast Encryption Demo\n";
    std::cout << "========================================\n";

    //----------------------------------------------------------
    // Setup
    //----------------------------------------------------------

    BroadcastEncryption be;

    if(!be.Setup())
    {
        std::cout << "Setup failed.\n";
        return -1;
    }

    std::cout << "[OK] Setup completed.\n";

    //----------------------------------------------------------
    // Create users
    //----------------------------------------------------------

    User alice;
    alice.id = 1;
    alice.name = "Alice";

    User bob;
    bob.id = 2;
    bob.name = "Bob";

    User charlie;
    charlie.id = 3;
    charlie.name = "Charlie";

    if(!be.KeyGen(alice))
        return -1;

    if(!be.KeyGen(bob))
        return -1;

    if(!be.KeyGen(charlie))
        return -1;

    std::cout << "[OK] Key Generation completed.\n";

    //----------------------------------------------------------
    // Access Policy
    //----------------------------------------------------------

    std::string policy =
        "(1 AND 2) OR 3";

    //----------------------------------------------------------
    // Encrypt
    //----------------------------------------------------------

    Header header;

    if(!be.Encrypt(policy, header))
    {
        std::cout << "Encryption failed.\n";
        return -1;
    }

    std::cout << "[OK] Encryption completed.\n";

    //----------------------------------------------------------
    // Partial Decryption
    //----------------------------------------------------------

    PartialKey p1;
    PartialKey p2;

    if(!be.PartialDecrypt(header, alice, p1))
    {
        std::cout << "Alice failed.\n";
        return -1;
    }

    if(!be.PartialDecrypt(header, bob, p2))
    {
        std::cout << "Bob failed.\n";
        return -1;
    }

    std::cout << "[OK] Partial decryptions completed.\n";

    //----------------------------------------------------------
    // Collaborative Decryption
    //----------------------------------------------------------

    std::vector<PartialKey> partials;

    partials.push_back(std::move(p1));
    partials.push_back(std::move(p2));

    SessionKey session;

    if(!be.CollaborativeDecrypt(
            header,
            partials,
            session))
    {
        std::cout << "Collaborative decryption failed.\n";
        return -1;
    }

    std::cout << "[OK] Collaborative decryption completed.\n";

    //----------------------------------------------------------
    // Print Session Key
    //----------------------------------------------------------

    std::cout << "\nRecovered Session Key:\n";

    PrintPoint(
        *be.GetPublicParameters().ecc,
        session.K.get());

    std::cout << "\n========================================\n";
    std::cout << " Demo Finished Successfully\n";
    std::cout << "========================================\n";

    return 0;
}