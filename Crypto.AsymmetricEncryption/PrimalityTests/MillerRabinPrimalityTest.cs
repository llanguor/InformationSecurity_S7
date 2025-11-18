using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public class MillerRabinPrimalityTest() :
    PrimalityTestBase(0.5)
{
    protected override bool PerformCoreCheck(BigInteger p, BigInteger a)
    {
        throw new NotImplementedException();
    }
}