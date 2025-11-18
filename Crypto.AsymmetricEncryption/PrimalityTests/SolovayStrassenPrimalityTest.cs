using System.Numerics;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.PrimalityTests;

public class SolovayStrassenPrimalityTest() :
    PrimalityTestBase(0.25)
{
    protected override bool PerformCoreCheck(BigInteger p, BigInteger a)
    {
        throw new NotImplementedException();
    }
}