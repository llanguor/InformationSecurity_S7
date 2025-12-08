using System.Numerics;

namespace Crypto.Attacks.RSA.Core;

public interface IRSAAttack
{
     BigInteger Perform(AsymmetricEncryption.RSA.RSAKey publicKey);
}