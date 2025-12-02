using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public sealed class SolovayStrassenPrimalityTest() :
    PrimalityTestBase(0.25)
{
    /// <inheritdoc/>
    protected override bool ValidateCondition(BigInteger n, BigInteger a)
    {
        if (n <= 2) 
            throw new ArgumentOutOfRangeException(nameof(n), "n must be greater than 2.");
        
        if (a <= 1 || a >= n) 
            throw new ArgumentOutOfRangeException(nameof(a), "a must be in range [2, n-1].");
        
        if(CryptoMathService.CalculateGcdEuclidean(n, a) != 1)
            return false;
  
        var powered = 
            CryptoMathService.ModPow(a, (n - 1) >> 1, n);
        
        var jacobi = 
            CryptoMathService.CalculateJacobiSymbol(a, n);
        
        if (powered == n-1)
            powered = BigInteger.MinusOne;
        
        return jacobi == powered;
    }
}