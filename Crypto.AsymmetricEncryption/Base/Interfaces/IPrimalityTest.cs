using System.Numerics;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface IPrimalityTest
{
    public PrimalityResult IsPrimary(
        BigInteger value, 
        double targetProbability);
}