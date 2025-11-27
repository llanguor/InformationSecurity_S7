namespace Crypto.AsymmetricEncryption;

public partial class RSA
{
    public enum RSAKeySize
    {
        /// <summary>
        /// 1024-bit RSA key. Not recommended for security; kept only for legacy compatibility.
        /// </summary>
        Bits1024 = 1024,

        /// <summary>
        /// 2048-bit RSA key. Minimum recommended size for most modern applications.
        /// </summary>
        Bits2048 = 2048,

        /// <summary>
        /// 3072-bit RSA key. Stronger long-term security; used when higher protection is required.
        /// </summary>
        Bits3072 = 3072,

        /// <summary>
        /// 4096-bit RSA key. Very strong security; slower operations. Common in high-security systems.
        /// </summary>
        Bits4096 = 4096
    }
}