using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;
namespace InformationSecurity.SymmetricEncryption.DataEncryptionStandard;

/// <summary>
/// Implementation of the <see cref="IKeyExpansion"/> interface for the DES algorithm.
/// Responsible for generating round keys from the original key.
/// </summary>
public sealed class DesKeyExpansion 
    : IKeyExpansion
{
    /// <inheritdoc/>
    public byte[][] Expand(byte[] key)
    {
        throw new NotImplementedException();
    }
}