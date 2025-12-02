using System.Numerics;

namespace Crypto.AsymmetricEncryption;


public sealed partial class RSA
{
    /// <summary>
    /// Represents an RSA key consisting of an exponent and a modulus.
    /// </summary>
    /// <param name="exponent">The exponent of the RSA key.</param>
    /// <param name="modulus">The modulus of the RSA key.</param>
    public sealed class RSAKey(
        BigInteger exponent,
        BigInteger modulus)
    {
        /// <summary>
        /// Gets the exponent of the RSA key.
        /// </summary>
        public BigInteger Exponent { get; } = exponent;
        
        /// <summary>
        /// Gets the modulus of the RSA key.
        /// </summary>
        public BigInteger Modulus { get; } = modulus;
    }
}