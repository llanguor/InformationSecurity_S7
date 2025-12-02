using Crypto.Core.Base.Interfaces;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base;

/// <summary>
/// Initializes a new instance of the <see cref="SymmetricPaddingBase"/> class
/// with the specified block size.
/// </summary>
/// <param name="blockSize">The size of each block for the padding scheme.</param>
public abstract class SymmetricPaddingBase (
    int blockSize)
    : ISymmetricPadding
{
    /// <summary>
    /// Gets the size of each block used by the padding scheme, in bytes.
    /// </summary>
    public int BlockSize { get; } = blockSize;
    
    /// <inheritdoc/>
    public abstract byte[] Apply(Span<byte> data);

    /// <inheritdoc/>
    public abstract byte[] Remove(Span<byte> data);
}