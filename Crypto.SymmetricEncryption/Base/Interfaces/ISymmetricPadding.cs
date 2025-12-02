using Crypto.Core.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base.Interfaces;

/// <summary>
/// Defines the contract for symmetric block padding algorithms.
/// Provides methods to apply and remove padding on data blocks.
/// </summary>
public interface ISymmetricPadding : ICipherPadding
{
    /// <summary>
    /// Gets the block size, in bytes, that the padding algorithm operates on.
    /// </summary>
    public int BlockSize { get; }
}