/******************************************************************************
*
* polynomial.cpp
*
* Original implementation
* RELIC Toolkit
*
******************************************************************************/

#include "polynomial.h"

using namespace std;


/******************************************************************************
*
* Generate random polynomial
*
******************************************************************************/

bool GeneratePolynomial(
        Polynomial &poly,
        int degree)
{
    poly.coef.clear();

    poly.coef.resize(degree + 1);

    bn_t order;

    bn_null(order);
    bn_new(order);

    g1_get_ord(order);

    for(int i = 0; i <= degree; i++)
    {
        bn_null(poly.coef[i]);
        bn_new(poly.coef[i]);

        bn_rand_mod(poly.coef[i], order);
    }

    bn_free(order);

    return true;
}


/******************************************************************************
*
* Evaluate polynomial
*
******************************************************************************/

bool EvaluatePolynomial(
        const Polynomial &poly,
        const bn_t x,
        bn_t result)
{
    bn_t order;
    bn_t power;
    bn_t term;
    bn_t tmp;

    bn_null(order);
    bn_null(power);
    bn_null(term);
    bn_null(tmp);

    bn_new(order);
    bn_new(power);
    bn_new(term);
    bn_new(tmp);

    g1_get_ord(order);

    bn_zero(result);

    bn_set_dig(power,1);

    for(size_t i=0;i<poly.coef.size();i++)
    {
        bn_mul(term,
               poly.coef[i],
               power);

        bn_mod(term,
               term,
               order);

        bn_add(tmp,
               result,
               term);

        bn_mod(result,
               tmp,
               order);

        bn_mul(power,
               power,
               x);

        bn_mod(power,
               power,
               order);
    }

    bn_free(order);
    bn_free(power);
    bn_free(term);
    bn_free(tmp);

    return true;
}


/******************************************************************************
*
* Compute Lagrange coefficient
*
******************************************************************************/

bool LagrangeCoefficient(
        const vector<bn_t> &points,
        int index,
        bn_t coeff)
{
    bn_t order;

    bn_null(order);
    bn_new(order);

    g1_get_ord(order);

    bn_set_dig(coeff,1);

    for(size_t j=0;j<points.size();j++)
    {
        if((int)j==index)
            continue;

        bn_t numerator;
        bn_t denominator;
        bn_t inverse;
        bn_t tmp;

        bn_null(numerator);
        bn_null(denominator);
        bn_null(inverse);
        bn_null(tmp);

        bn_new(numerator);
        bn_new(denominator);
        bn_new(inverse);
        bn_new(tmp);

        /*
            numerator = -x_j
        */

        bn_neg(numerator, points[j]);
        bn_mod(numerator, numerator, order);

        /*
            denominator = x_i-x_j
        */

        bn_sub(
            denominator,
            points[index],
            points[j]);

        bn_mod(
            denominator,
            denominator,
            order);

        if(bn_is_zero(denominator))
        {
            bn_free(order);

            bn_free(numerator);
            bn_free(denominator);
            bn_free(inverse);
            bn_free(tmp);

            return false;
        }

        bn_mod_inv(
            inverse,
            denominator,
            order);

        bn_mul(
            tmp,
            numerator,
            inverse);

        bn_mod(
            tmp,
            tmp,
            order);

        bn_mul(
            coeff,
            coeff,
            tmp);

        bn_mod(
            coeff,
            coeff,
            order);

        bn_free(numerator);
        bn_free(denominator);
        bn_free(inverse);
        bn_free(tmp);
    }

    bn_free(order);

    return true;
}


/******************************************************************************
*
* Free polynomial
*
******************************************************************************/

void FreePolynomial(
        Polynomial &poly)
{
    for(size_t i=0;i<poly.coef.size();i++)
    {
        bn_free(poly.coef[i]);
    }

    poly.coef.clear();
}