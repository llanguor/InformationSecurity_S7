using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption;

public class CryptoMathService :
    ICryptoMathService
{
    public int CalculateLegendreSymbol(
        BigInteger a,
        BigInteger p)
    {
        throw new NotImplementedException();
    }

    public int CalculateJacobiSymbol(
        BigInteger a,
        BigInteger p)
    {
        throw new NotImplementedException();
    }

    public BigInteger ModPow(
        BigInteger baseValue,
        BigInteger exponent,
        BigInteger modulus)
    {
        throw new NotImplementedException();
    }

    public BigInteger CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b)
    {
        throw new NotImplementedException();
    }

    public void CalculateGcdEuclideanExtended(
        BigInteger a,
        BigInteger b,
        out BigInteger gcd, 
        out BigInteger x,
        out BigInteger y)
    {
        throw new NotImplementedException();
    }
}