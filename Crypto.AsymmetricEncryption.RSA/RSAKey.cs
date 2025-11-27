using System.Numerics;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA
{
    public sealed class RSAKey(
        BigInteger exponent,
        BigInteger modulus)
    {
        public BigInteger Exponent { get; } = exponent;
        
        public BigInteger Modulus { get; } = modulus;
    }
}