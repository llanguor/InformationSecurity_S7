using System.Numerics;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface IKeyGenerator
{
    public void GenerateKeys(
        out byte[] publicKey,
        out byte[] privateKey);
}