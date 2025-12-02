using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public sealed class SolovayStrassenPrimalityTest() :
    PrimalityTestBase(0.25)
{
    /// <inheritdoc/>
    protected override bool ValidateCondition(BigInteger n, BigInteger a)
    {
        if(CryptoMathService.CalculateGcdEuclidean(n, a) != 1)
            return false;
  
        var powered = 
            CryptoMathService.ModPow(a, (n - 1) >> 1, n);
        
        var jacobi = 
            CryptoMathService.CalculateJacobiSymbol(a, n);
        
        if (powered == n-1)
            powered = -1;
        
        return jacobi == powered;
    }
}