using Crypto.Core.Base.Interfaces;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base;

/// <summary>
/// Initializes a new instance of the <see cref="SymmetricPaddingBase"/> class
/// with the specified block size.
/// </summary>
public abstract class SymmetricPaddingBase : 
    ISymmetricPadding
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SymmetricPaddingBase"/> class
    /// with the specified block size.
    /// </summary>
    /// <param name="blockSize">The size of each block for the padding scheme.</param>
    protected SymmetricPaddingBase(int blockSize)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be positive.");
        
        BlockSize = blockSize;
    }

    /// <summary>
    /// Gets the size of each block used by the padding scheme, in bytes.
    /// </summary>
    public int BlockSize { get; }
    
    /// <inheritdoc/>
    public abstract byte[] Apply(Span<byte> data);

    /// <inheritdoc/>
    public abstract byte[] Remove(Span<byte> data);
}