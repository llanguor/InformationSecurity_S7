using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public class MillerRabinPrimalityTest() :
    PrimalityTestBase(0.5)
{
    protected override bool PerformCoreCheck(BigInteger n, BigInteger a)
    {
        return CryptoMathService.ModPow(a, (n - 1) >> 1, n) ==
               CryptoMathService.CalculateJacobiSymbol(a, n);
    }
}