using System.Numerics;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface IKeyGenerator<TKey>
{
    public void GenerateKeys(
        out TKey publicKey,
        out TKey privateKey);
}