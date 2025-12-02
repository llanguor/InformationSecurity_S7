using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption;

/// <summary>
/// Provides mathematical operations used in asymmetric cryptography, such as
/// Legendre and Jacobi symbols, modular exponentiation, and Euclidean GCD calculations.
/// </summary>
public sealed class CryptoMathService :
    ICryptoMathService
{
    #region Public methods
    
    /// <summary>
    /// Calculates the Legendre symbol (a/p), which indicates whether 'a' is a quadratic residue modulo 'p'.
    /// </summary>
    /// <param name="a">The integer whose quadratic residuosity is evaluated.</param>
    /// <param name="p">A prime modulus greater than 2.</param>
    /// <returns>1 if 'a' is a quadratic residue modulo 'p', -1 if it is a non-residue, 0 if gcd(a, p) != 1.</returns>
    /// <exception cref="ArgumentException">Thrown if 'p' is less than or equal to 2.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the computed value is unexpected, indicating 'p' may not be prime.</exception>
    public int CalculateLegendreSymbol(
        BigInteger a,
        BigInteger p)
    {
        if (p <= 2)
            throw new ArgumentException(
                "The Legendre symbol is defined only for numbers greater than 2", nameof(p));
        
        if (CalculateGcdEuclidean(a, p) != 1)
            return 0;

        var powered = 
            ModPow(a, (p - 1) >> 2, p);

        if (powered < 0)
            powered += p;
        
        if (powered == 1)
            return 1;
        
        if (powered == p - 1)
            return -1;
            
        throw new InvalidOperationException(
            "The Legendre symbol returned an unexpected value. Ensure that p is indeed a prime number.");
    }

    /// <summary>
    /// Calculates the Jacobi symbol (a/n), a generalization of the Legendre symbol for any odd integer 'n'.
    /// </summary>
    /// <param name="a">The integer whose Jacobi symbol is computed.</param>
    /// <param name="n">An odd integer greater than 1.</param>
    /// <returns>The Jacobi symbol value: 1, -1, or 0.</returns>
    /// <exception cref="ArgumentException">Thrown if 'n' is even or less than or equal to 1.</exception>
    public int CalculateJacobiSymbol(
        BigInteger a,
        BigInteger n)
    {
        if (n <= 1 || (n & 1) == 0)
            throw new ArgumentException(
                $"Parameter {nameof(n)} must be an odd integer greater than 1.", nameof(n));
        
        var result = 1;
        a = BigInteger.Abs(a);
        a %= n;
        
        while (a != 0)
        {
            //divide by 2 until parameter 'a' is even
            while ((a & 1) == 0)
            {
                a >>= 1;
                var rem8 = n % 8;
                if (rem8 == 3 ||
                    rem8 == 5)
                {
                    result = -result;
                }
            }
            
            //quadratic reciprocity property of the Jacobi symbol
            (a, n) = (n, a);
            if (a % 4 == 3 &&
                n % 4 == 3)
            {
                result *= -1;
            }

            a %= n;
        }

        return n == 1 ? result : 0;
    }

    /// <summary>
    /// Performs modular exponentiation: calculates (baseValue^exponent) mod modulus efficiently.
    /// </summary>
    /// <param name="baseValue">The base integer.</param>
    /// <param name="exponent">The non-negative exponent.</param>
    /// <param name="modulus">The positive modulus.</param>
    /// <returns>The result of modular exponentiation.</returns>
    /// <exception cref="ArgumentException">Thrown if 0^0 is attempted, exponent is negative, or modulus is non-positive.</exception>
    public BigInteger ModPow(
        BigInteger baseValue,
        BigInteger exponent,
        BigInteger modulus)
    {
        if (baseValue == 0 && exponent == 0)
            throw new ArgumentException(
                "Cannot raise 0 to the power of 0");
        
        if (exponent < 0)
            throw new ArgumentException("Exponent must be non-negative", nameof(exponent));
        
        if (modulus <= 0)
            throw new ArgumentException("Modulus must be positive", nameof(modulus));

        var result = BigInteger.One;
        baseValue %= modulus;

        while (exponent != BigInteger.Zero)
        {
            if((exponent & BigInteger.One) == BigInteger.One)
                result = result * baseValue % modulus;
            
            baseValue = baseValue * baseValue % modulus;
            exponent >>= 1;
        }
        
        return result;
    }
    
    /// <summary>
    /// Calculates the greatest common divisor (GCD) of two integers using the Euclidean algorithm.
    /// </summary>
    /// <param name="a">The first integer.</param>
    /// <param name="b">The second integer.</param>
    /// <returns>The greatest common divisor of 'a' and 'b'.</returns>
    public BigInteger CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b)
    {
        while (b != 0)
        {
            var temp = b;
            b = a % b;
            a = temp;
        }

        if (a < 0)
            a += b;
        
        return BigInteger.Abs(a);
    }

    /// <summary>
    /// Calculates the greatest common divisor (GCD) of two integers along with
    /// coefficients x and y such that a*x + b*y = gcd(a, b), using the extended Euclidean algorithm.
    /// </summary>
    /// <param name="a">The first integer.</param>
    /// <param name="b">The second integer.</param>
    /// <param name="gcd">Output parameter for the greatest common divisor.</param>
    /// <param name="x">Output parameter for the coefficient corresponding to 'a'.</param>
    /// <param name="y">Output parameter for the coefficient corresponding to 'b'.</param>
    public void CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b,
        out BigInteger gcd, 
        out BigInteger x,
        out BigInteger y)
    {
        gcd = a;
        x = BigInteger.One;
        y = BigInteger.Zero;
        var currGcd = b;
        var currX = BigInteger.Zero;
        var currY = BigInteger.One;

        while (currGcd != 0)
        {
            var quotient = gcd / currGcd;
            
            (gcd, currGcd) = 
                (currGcd, gcd - quotient * currGcd);
            
            (x, currX) = 
                (currX, x - quotient * currX);
            
            (y, currY) = 
                (currY, y - quotient * currY);
        }
        
        if (gcd < 0)
        {
            gcd = -gcd;
            x = -x;
            y = -y;
        }
    }
    
    #endregion
}