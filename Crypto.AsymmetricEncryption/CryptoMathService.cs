using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption;

public class CryptoMathService :
    ICryptoMathService
{
    #region Public methods
    
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
        while (b != 0)
        {
            var temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    public void CalculateGcdEuclidean(
        BigInteger a,
        BigInteger b,
        out BigInteger gcd, 
        out BigInteger x,
        out BigInteger y)
    {
        gcd = a;
        x = BigInteger.One;
        y = BigInteger.Zero;
        var currGcd = b;
        var currX = BigInteger.Zero;
        var currY = BigInteger.One;

        while (currGcd != 0)
        {
            var quotient = gcd / currGcd;
            
            (gcd, currGcd) = (currGcd, gcd - quotient * currGcd);
            
            (x, currX) = (currX, x - quotient * currX);
            
            (y, currY) = (currY, y - quotient * currY);
        }
    }
    
    #endregion
    
    #region Private methods

    private void Foo()
    {
        
    }
    
    #endregion
}