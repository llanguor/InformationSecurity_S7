namespace Crypto.AsymmetricEncryption.Base.Interfaces;

/// <summary>
/// Defines a generator for asymmetric cryptographic key pairs of type <typeparamref name="TKey"/>.
/// </summary>
public interface IKeyGenerator<TKey>
{
    /// <summary>
    /// Generates a new asymmetric key pair.
    /// </summary>
    /// <param name="publicKey">Output parameter for the generated public key.</param>
    /// <param name="privateKey">Output parameter for the generated private key.</param>
    public void GenerateKeys(
        out TKey publicKey,
        out TKey privateKey);
}