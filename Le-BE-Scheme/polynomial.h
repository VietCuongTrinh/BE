#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include "params.h"

/**
 * Generate a random polynomial
 *
 * P(x)=a0+a1x+...+adxd
 */
bool GeneratePolynomial(
        Polynomial &poly,
        int degree);

/**
 * Evaluate polynomial at x
 *
 * result=P(x)
 */
bool EvaluatePolynomial(
        const Polynomial &poly,
        const bn_t x,
        bn_t result);

/**
 * Compute Lagrange coefficient
 *
 * λ_i(0)
 */
bool LagrangeCoefficient(
        const std::vector<bn_t> &points,
        int index,
        bn_t coeff);

/**
 * Free memory occupied by a polynomial
 */
void FreePolynomial(
        Polynomial &poly);

#endif