using System.Numerics;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

/// <summary>
/// Provides methods to test whether a given integer is prime.
/// </summary>
public interface IPrimalityTest
{
    /// <summary>
    /// Determines whether the specified integer is prime with a given confidence probability.
    /// </summary>
    /// <param name="value">The integer value to test for primality.</param>
    /// <param name="targetProbability">The desired probability of correctness for the primality test.</param>
    /// <returns>A <see cref="PrimalityResult"/> indicating if the number is prime or composite.</returns>
    public PrimalityResult IsPrimary(
        BigInteger value, 
        double targetProbability);
}