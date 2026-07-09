/******************************************************************************
*
* utils.cpp
*
* Utility Functions
* RELIC Toolkit + BLS12-381
*
******************************************************************************/

#include "mtbe.h"

#include <iostream>
#include <iomanip>
#include <chrono>

using namespace std;
using namespace std::chrono;

static high_resolution_clock::time_point timerStart;


/******************************************************************************
*
* Timer
*
******************************************************************************/

void StartTimer()
{
    timerStart = high_resolution_clock::now();
}

double StopTimer()
{
    auto timerEnd = high_resolution_clock::now();

    duration<double, milli> elapsed =
            timerEnd - timerStart;

    return elapsed.count();
}

double GetCurrentTime()
{
    auto t = high_resolution_clock::now();

    duration<double, milli> elapsed =
            t.time_since_epoch();

    return elapsed.count();
}


/******************************************************************************
*
* Print Big Number
*
******************************************************************************/

void PrintBN(const bn_t value)
{
    int len = bn_size_str(value, 16);

    char *buffer = new char[len + 1];

    bn_write_str(buffer,
                 len + 1,
                 value,
                 16);

    cout << buffer << endl;

    delete[] buffer;
}


/******************************************************************************
*
* Print G1
*
******************************************************************************/

void PrintG1(const g1_t value)
{
    int len = g1_size_bin(value, 1);

    uint8_t *buffer = new uint8_t[len];

    g1_write_bin(buffer,
                 len,
                 value,
                 1);

    cout << "G1[";

    for(int i=0;i<len;i++)
    {
        cout << hex
             << setw(2)
             << setfill('0')
             << (int)buffer[i];
    }

    cout << "]" << endl;

    delete[] buffer;
}


/******************************************************************************
*
* Print G2
*
******************************************************************************/

void PrintG2(const g2_t value)
{
    int len = g2_size_bin(value, 1);

    uint8_t *buffer = new uint8_t[len];

    g2_write_bin(buffer,
                 len,
                 value,
                 1);

    cout << "G2[";

    for(int i=0;i<len;i++)
    {
        cout << hex
             << setw(2)
             << setfill('0')
             << (int)buffer[i];
    }

    cout << "]" << endl;

    delete[] buffer;
}


/******************************************************************************
*
* Print GT
*
******************************************************************************/

void PrintGT(const gt_t value)
{
    int len = gt_size_bin(value, 1);

    uint8_t *buffer = new uint8_t[len];

    gt_write_bin(buffer,
                 len,
                 value,
                 1);

    cout << "GT[";

    for(int i=0;i<len;i++)
    {
        cout << hex
             << setw(2)
             << setfill('0')
             << (int)buffer[i];
    }

    cout << "]" << endl;

    delete[] buffer;
}


/******************************************************************************
*
* Save Public Parameters
*
******************************************************************************/

bool SavePublicParams(
        const PublicParams &,
        const string &)
{
    /*
        Placeholder

        Later versions can serialize

            g
            g_tilde
            alphaPower
            eggP0
            dummy keys
    */

    return true;
}


/******************************************************************************
*
* Load Public Parameters
*
******************************************************************************/

bool LoadPublicParams(
        PublicParams &,
        const string &)
{
    return true;
}


/******************************************************************************
*
* Save Secret Key
*
******************************************************************************/

bool SaveSecretKey(
        const SecretKey &,
        const string &)
{
    return true;
}


/******************************************************************************
*
* Load Secret Key
*
******************************************************************************/

bool LoadSecretKey(
        SecretKey &,
        const string &)
{
    return true;
}