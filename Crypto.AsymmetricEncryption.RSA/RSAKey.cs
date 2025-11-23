using System.Numerics;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA
{
    public sealed class RSAKey(
        BigInteger modulus,
        BigInteger exponent)
    {
        public BigInteger Modulus { get; } = modulus;
        
        public BigInteger Exponent { get; } = exponent;
    }
}