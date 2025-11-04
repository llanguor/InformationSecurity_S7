namespace InformationSecurity.SymmetricEncryption;

/// <summary>
/// Provides methods for performing bit-level transformations used in symmetric encryption algorithms,
/// including permutation and substitution operations. These operations allow reordering or replacing bits
/// according to defined masks or substitution rules.
/// </summary>
public static class PermutationSubstitution
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
    /// <param name="startingBitIndex">Specifies the index of the starting bit in the input bytes set.=</param>
    /// <param name="inputLsbPosition">Specifies the order of bit numbering in bytes in the input value.</param>
    /// <param name="outputLsbPosition">Specifies the order of bit numbering in bytes in the output value.</param>
    /// <returns>Returns a set of bits with permuted values.</returns>
    public static Span<byte> Permute(
        Span<byte> bytes, 
        ReadOnlySpan<int> mask,
        StartingBitIndex startingBitIndex,
        LeastSignificantBitPosition inputLsbPosition,
        LeastSignificantBitPosition outputLsbPosition)
    {
        Span<byte> result = new byte[bytes.Length];
        
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
                    result.Length - 1 - i / 8;
            
            result[byteIndex] &= (byte) ~(1 << bitIndex);
            result[byteIndex] |= (byte)(bitValue << bitIndex);
        }
        
        return result;
    }

    public static void Substitute(
        Span<byte> bytes, 
        ReadOnlySpan<int> mask,
        StartingBitIndex startingBitIndex)
    {
        
    }
}