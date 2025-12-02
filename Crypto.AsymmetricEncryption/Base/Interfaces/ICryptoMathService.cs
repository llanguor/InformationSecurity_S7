using System.Numerics;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

/// <summary>
/// Provides mathematical operations commonly used in asymmetric cryptography,
/// including modular exponentiation, greatest common divisor calculation, and symbol computations.
/// </summary>
public interface ICryptoMathService
{
    /// <summary>
    /// Calculates the Legendre symbol (a/p).
    /// </summary>
    /// <param name="a">The integer numerator.</param>
    /// <param name="p">The odd prime denominator.</param>
    /// <returns>1 if a is a quadratic residue modulo p, -1 if a is a non-residue, 0 if a is divisible by p.</returns>
    public int CalculateLegendreSymbol(
        BigInteger a,
        BigInteger p);
    
    /// <summary>
    /// Calculates the Jacobi symbol (a/p).
    /// </summary>
    /// <param name="a">The integer numerator.</param>
    /// <param name="p">The (odd) denominator, can be composite.</param>
    /// <returns>Value of the Jacobi symbol: 1, -1, or 0.</returns>
    public int CalculateJacobiSymbol(
        BigInteger a,
        BigInteger p);

    /// <summary>
    /// Computes modular exponentiation: (baseValue^exponent) mod modulus.
    /// </summary>
    /// <param name="baseValue">The base integer.</param>
    /// <param name="exponent">The exponent integer.</param>
    /// <param name="modulus">The modulus integer.</param>
    /// <returns>The result of (baseValue^exponent) modulo modulus.</returns>
    public BigInteger ModPow(BigInteger baseValue,
        BigInteger exponent,
        BigInteger modulus);
    
    /// <summary>
    /// Calculates the greatest common divisor (GCD) of two integers using the Euclidean algorithm.
    /// </summary>
    /// <param name="a">First integer.</param>
    /// <param name="b">Second integer.</param>
    /// <returns>The greatest common divisor of a and b.</returns>
    public BigInteger CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b);
    
    /// <summary>
    /// Calculates the greatest common divisor (GCD) of two integers using the extended Euclidean algorithm.
    /// Also computes integers x and y such that gcd = a*x + b*y.
    /// </summary>
    /// <param name="a">First integer.</param>
    /// <param name="b">Second integer.</param>
    /// <param name="gcd">Output greatest common divisor of a and b.</param>
    /// <param name="x">Output coefficient for a in the linear combination.</param>
    /// <param name="y">Output coefficient for b in the linear combination.</param>
    public void CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b,
        out BigInteger gcd,
        out BigInteger x,
        out BigInteger y);
}