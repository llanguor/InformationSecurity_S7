using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;
namespace InformationSecurity.SymmetricEncryption.DataEncryptionStandard;

/// <summary>
/// Implementation of the <see cref="IRoundFunction"/> interface for the DES algorithm.
/// Represents the round function (F-function) used in the DES Feistel network.
/// </summary>
public sealed class DesRoundFunction 
    : IRoundFunction
{
    /// <inheritdoc/>
    public byte[] TransformBlock(byte[] block, byte[] key)
    {
        throw new NotImplementedException();
    }
}