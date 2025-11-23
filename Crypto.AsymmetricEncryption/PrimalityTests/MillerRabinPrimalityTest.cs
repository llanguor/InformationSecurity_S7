using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public sealed class MillerRabinPrimalityTest() :
    PrimalityTestBase(0.5)
{
    protected override bool ValidateCondition(BigInteger n, BigInteger a)
    {
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