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
        if (p <= 2)
            throw new ArgumentException(
                "The Legendre symbol is defined only for numbers greater than 2", nameof(p));
        
        if (CalculateGcdEuclidean(a, p) != 1)
            return 0;

        var powered = 
            ModPow(a, (p - 1) >> 2, p);

        if (powered < 0)
            powered += p;
        
        if (powered == 1)
            return 1;
        
        if (powered == p - 1)
            return -1;
            
        throw new InvalidOperationException(
            "The Legendre symbol returned an unexpected value. Ensure that p is indeed a prime number.");
    }

    public int CalculateJacobiSymbol(
        BigInteger a,
        BigInteger n)
    {
        if (n <= 1 || (n & 1) == 0)
            throw new ArgumentException(
                $"Parameter {nameof(n)} must be an odd integer greater than 1.", nameof(n));
        
        var result = 1;
        a = BigInteger.Abs(a);
        a %= n;
        
        while (a != 0)
        {
            //divide by 2 until parameter 'a' is even
            while ((a & 1) == 0)
            {
                a >>= 1;
                var rem8 = n % 8;
                if (rem8 == 3 ||
                    rem8 == 5)
                {
                    result = -result;
                }
            }
            
            //quadratic reciprocity property of the Jacobi symbol
            (a, n) = (n, a);
            if (a % 4 == 3 &&
                n % 4 == 3)
            {
                result *= -1;
            }

            a %= n;
        }

        return n == 1 ? result : 0;
    }

    public BigInteger ModPow(
        BigInteger baseValue,
        BigInteger exponent,
        BigInteger modulus)
    {
        if (baseValue == 0 && exponent == 0)
            throw new ArgumentException(
                "Cannot raise 0 to the power of 0");
        
        if (exponent < 0)
            throw new ArgumentException("Exponent must be non-negative", nameof(exponent));
        
        if (modulus <= 0)
            throw new ArgumentException("Modulus must be positive", nameof(modulus));

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

        if (a < 0)
            a += b;
        
        return BigInteger.Abs(a);
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
            
            (gcd, currGcd) = 
                (currGcd, gcd - quotient * currGcd);
            
            (x, currX) = 
                (currX, x - quotient * currX);
            
            (y, currY) = 
                (currY, y - quotient * currY);
        }
        
        if (gcd < 0)
        {
            gcd = -gcd;
            x = -x;
            y = -y;
        }
    }
    
    #endregion
}