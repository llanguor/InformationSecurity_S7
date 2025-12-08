using System.Numerics;
using Crypto.AsymmetricEncryption;

namespace Crypto.Attacks.RSA.Core;

public sealed class MathService
{
    private readonly CryptoMathService _mathService = new();
    
    /// <summary>
    /// Computes the continued fraction expansion of the rational number
    /// represented by <paramref name="numerator"/> divided by
    /// <paramref name="denominator"/>. The method performs the standard
    /// Euclidean algorithm and extracts the sequence of partial quotients
    /// that define the continued fraction. The numerator and denominator
    /// must be coprime (mutually prime) integers.
    /// </summary>
    /// <param name="numerator">
    /// The numerator of the rational number to be expanded.
    /// </param>
    /// <param name="denominator">
    /// The denominator of the rational number to be expanded.
    /// Must be nonzero.
    /// </param>
    /// <returns>
    /// An array of integers representing the partial quotients of the
    /// continued fraction expansion of the specified rational number.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="denominator"/> is zero or negative,
    /// or when <paramref name="numerator"/> and <paramref name="denominator"/>
    /// are not coprime (mutually prime).
    /// </exception>
    public BigInteger[] ComputeContinuedFraction(BigInteger numerator, BigInteger denominator)
    {
        if (denominator <= 0)
            throw new ArgumentException("Denominator must be positive.");

        if (_mathService.CalculateGcdEuclidean(numerator, denominator) != 1)
            throw new ArgumentException("Numerator and denominator must be coprime.");
        
        
        var isNegative = numerator < 0;
        if (isNegative)
            numerator = -numerator;
        
        var result = new List<BigInteger>();
            
        while (numerator > 0 && denominator > 0)
        {
            result.Add(numerator / denominator);
            var remainder = numerator % denominator;
            numerator = denominator;
            denominator = remainder;
        }
        
        if (isNegative)
            result[0] = -result[0];
        
        return result.ToArray();
    }

    /// <summary>
    /// Builds the sequence of convergents for a continued fraction
    /// specified by its coefficient array.
    /// </summary>
    /// <param name="coefficients">The coefficients of the continued fraction.</param>
    /// <returns>
    /// An array of tuples (numerator, denominator), where each element
    /// represents a successive convergent of the continued fraction.
    /// </returns>
    public Tuple<BigInteger, BigInteger>[] GetConvergentsFractions(BigInteger[] coefficients)
    {
        //todo: exceptions
        
        var result = new List<Tuple<BigInteger, BigInteger>>
        {
            new Tuple<BigInteger, BigInteger>(1, 0),
            new Tuple<BigInteger, BigInteger>(coefficients[0], 1)
        };

        for (var i = 1; i < coefficients.Length; ++i)
        {
            result.Add(
                new Tuple<BigInteger, BigInteger>(
                    result[^1].Item1 * coefficients[i] + result[^2].Item1,
                    result[^1].Item2 * coefficients[i] + result[^2].Item2));
        }

        return result.ToArray();
    }

    /// <summary>
    /// Computes the continued fraction representation of the given rational
    /// number and returns the sequence of its convergents.
    /// </summary>
    /// <param name="numerator">The numerator of the rational number.</param>
    /// <param name="denominator">The denominator of the rational number.</param>
    /// <returns>
    /// An array of convergents obtained from the continued fraction expansion
    /// of the specified rational number.
    /// </returns>
    public Tuple<BigInteger, BigInteger>[] GetConvergentsFractions(BigInteger numerator, BigInteger denominator)
    {
        
        return GetConvergentsFractions(
            ComputeContinuedFraction(
                numerator, 
                denominator));
    }
    
    //todo: change
    private BigInteger Sqrt(BigInteger n)
    {
        if (n == 0)
            return 0;
        
        var x = n / 2 + 1;
        var y = (x + n / x) / 2;
        
        while (y < x)
        {
            x = y;
            y = (x + n / x) / 2;
        }
        return x;
    }

    /// <summary>
    /// Solves the quadratic equation ax² + bx + c = 0
    /// and returns only natural (positive integer) roots.  
    /// If any of the roots are not natural (not divisible, zero, negative, 
    /// or if the discriminant is not a perfect square), the method returns an empty array.  
    /// This is intended for use in the context of Wiener's attack.
    /// </summary>
    /// <param name="a">Coefficient of x² (must be non-zero for a true quadratic equation).</param>
    /// <param name="b">Coefficient of x.</param>
    /// <param name="c">Constant term.</param>
    /// <returns>
    /// An array containing the two natural roots if both are valid, 
    /// or an empty array if any root is invalid.
    /// </returns>
    public BigInteger[] SolveQuadraticForWienersAttack(
        BigInteger a,
        BigInteger b,
        BigInteger c)
    {
        if (a == 0) 
            return (b == 0) || (-c % b != 0) ? [] : [-c / b];

        var discriminant =
            b * b - 4 * a * c;
        
        //==0: two identical roots are incorrect from an RSA point of view
        if (discriminant <= 0)
            return [];
        
        
        var sqrtD = _mathService.Sqrt(
            discriminant,
            out var fractional,
            9);
        if (fractional != 0)
            return [];
        
        var denominator = 2 * a;
        var numerator1 = -b + sqrtD;
        var numerator2 = -b - sqrtD;
        
        if (numerator1 % denominator != 0 ||
            numerator2 % denominator != 0)
            return [];

        var x1 = numerator1 / denominator;
        var x2 = numerator2 / denominator;
        
        if (x1 <= 0 || x2 <= 0)
            return [];

        return [x1, x2];
    }
}















