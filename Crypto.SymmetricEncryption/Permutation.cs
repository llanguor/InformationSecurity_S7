namespace Crypto.SymmetricEncryption;

/// <summary>
/// Provides methods for performing bit-level transformations used in symmetric encryption algorithms,
/// including permutation and substitution operations. These operations allow reordering or replacing bits
/// according to defined masks or substitution rules.
/// </summary>
public static class Permutation
{
    /// <summary>
    /// Specifies the order of bit numbering in bytes.
    /// </summary>
    public enum LeastSignificantBitPosition
    {
        /// <summary>Bits are numbered from left to right.</summary>
        Left = 0,
        
        /// <summary>Bits are numbered from right to left.</summary>
        Right = 1
    }

    /// <summary>
    /// Specifies the index of the starting bit in the input bytes set.
    /// </summary>
    public enum StartingBitIndex
    {
        /// <summary>A bit numbering starts from 0</summary>
        Zero = 0,
        
        /// <summary>A bit numbering starts from 1</summary>
        First = 1
    }
    
    /// <summary>
    /// Performs a permutation of bits in the source byte set according to the specified mask.
    /// </summary>
    /// <param name="bytes">A set of bytes.</param>
    /// <param name="mask">Mask for performing permutations.</param>
    /// <param name="output">
    /// The buffer that receives the permuted bits.
    /// The size must be equal to or larger than the mask
    /// </param>
    /// <param name="startingBitIndex">Specifies the index of the starting bit in the input bytes set.=</param>
    /// <param name="inputLsbPosition">Specifies the order of bit numbering in bytes in the input value.</param>
    /// <param name="outputLsbPosition">Specifies the order of bit numbering in bytes in the output value.</param>
    public static void Permute(
        ReadOnlySpan<byte> bytes, 
        ReadOnlySpan<int> mask,
        Span<byte> output,
        StartingBitIndex startingBitIndex,
        LeastSignificantBitPosition inputLsbPosition,
        LeastSignificantBitPosition outputLsbPosition)
    {
        if (bytes.IsEmpty)
            throw new ArgumentException("Input bytes cannot be empty.", nameof(bytes));
        if (mask.IsEmpty)
            throw new ArgumentException("Mask cannot be empty.", nameof(mask));
        if (output.IsEmpty)
            throw new ArgumentException("Output buffer cannot be empty.", nameof(output));
        if (output.Length * 8 < mask.Length)
            throw new ArgumentException("Output buffer is too small for the mask.", nameof(output));
        
        for (var i = 0; i < mask.Length; i++)
        {
            var targetIndex = mask[i] - (int)startingBitIndex;
            var bitValue =
                inputLsbPosition == LeastSignificantBitPosition.Left ?
                    (bytes[targetIndex/8] >> (7 - targetIndex % 8)) & 1 :
                    (bytes[bytes.Length - 1 - targetIndex/8] >> (7-targetIndex%8)) & 1;
            
            var bitIndex = 7 - i % 8;
            var byteIndex =
                outputLsbPosition == LeastSignificantBitPosition.Left ? 
                    i / 8 : 
                    output.Length - 1 - i / 8;
    
            output[byteIndex] &= (byte) ~(1 << bitIndex);
            output[byteIndex] |= (byte)(bitValue << bitIndex);
        }
    }
}