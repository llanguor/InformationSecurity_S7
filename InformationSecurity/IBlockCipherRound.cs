namespace InformationSecurity;

/// <summary>
/// Represents a single round transformation in a block cipher.
/// Performs encryption on a single block using a specified round key.
/// </summary>
public interface IBlockCipherRound
{
    /// <summary>
    /// Transforms the input block using the provided round key.
    /// This method represents one round of a block cipher.
    /// </summary>
    /// <param name="block">The input block to be transformed.</param>
    /// <param name="key">The round key to use for transformation.</param>
    /// <returns>The transformed output block as a byte array.</returns>
    byte[] TransformBlock(byte[] block, byte[] key);
}