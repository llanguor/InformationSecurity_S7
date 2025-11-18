using System.Numerics;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface ICryptoMathService
{
    public int CalculateLegendreSymbol(
        BigInteger a,
        BigInteger p);
    
    public int CalculateJacobiSymbol(
        BigInteger a,
        BigInteger p);

    public BigInteger ModPow(BigInteger baseValue,
        BigInteger exponent,
        BigInteger modulus);
    
    public BigInteger CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b);
    
    public void CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b,
        out BigInteger gcd,
        out BigInteger x,
        out BigInteger y);
}