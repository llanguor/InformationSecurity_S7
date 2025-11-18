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
        var result = BigInteger.One;
        baseValue %= modulus;

        while (exponent != BigInteger.Zero)
        {
            if((exponent & BigInteger.One) == BigInteger.One)
                result = result * baseValue % modulus;
            
            baseValue = baseValue * baseValue % modulus;
            exponent >>= 1;
        }
        
        return result;
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