namespace Crypto.SymmetricEncryption.Base.Interfaces;

/// <summary>
/// Represents a single round transformation in a block cipher.
/// Performs encryption on a single block using a specified round key.
/// </summary>
public interface IRoundFunction
{
    /// <summary>
    /// Transforms input block using the specified 48-bit round key.
    /// Represents one round of the Feistel network (F-function).
    /// The <paramref name="block"/> parameter is modified <c>in-place</c>.
    /// </summary>
    /// <param name="block">
    /// The input block to be transformed.
    /// the block is modified in-place.
    /// </param>
    /// <param name="key">The round key to use for transformation.</param>
    /// /// <returns>
    /// The same <paramref name="block"/> after transformation.
    /// Although the block is modified in-place, the method also returns
    /// it for convenience, allowing inline usage or method chaining.
    /// </returns>
    byte[] TransformBlock(byte[] block, byte[] key);
}