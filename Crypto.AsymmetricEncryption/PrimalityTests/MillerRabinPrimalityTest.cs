using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

/// <summary>
/// Implements the Miller-Rabin probabilistic primality test using <see cref="PrimalityTestBase"/>.
/// Determines whether a number is likely prime based on repeated modular exponentiation checks.
/// </summary>
public sealed class MillerRabinPrimalityTest() :
    PrimalityTestBase(0.5)
{
    /// <inheritdoc/>
    protected override bool ValidateCondition(BigInteger n, BigInteger a)
    {
        if (n <= 2) 
            throw new ArgumentOutOfRangeException(nameof(n), "n must be greater than 2.");
        if (a <= 1 || a >= n)
            throw new ArgumentOutOfRangeException(nameof(a), "a must be in range [2, n-1].");
        
        var s = 0;
        var d = n - 1;
        while ((d & 1) == 0)
        {
            d >>= 1; 
            ++s;
        }

        var powered =
            CryptoMathService.ModPow(a, d, n);
        if (powered == 1 || powered == n-1)
            return true;
        
        for (var i = 1; i <= s; ++i)
        {
            powered = (powered * powered) % n; 
            
            if (powered == n-1)
            {
                return true;
            }
        }

        return false;
    }
}