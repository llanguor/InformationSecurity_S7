namespace InformationSecurity;

public sealed class SpNetwork
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
        /// <summary>Bit numbering starts from 0</summary>
        Zero = 0,
        
        /// <summary>Bit numbering starts from 1</summary>
        First = 1
    }
    
    /// <summary>
    /// Performs a bit permutation on the source set of bytes following the given mask.
    /// </summary>
    /// <param name="bytes">A set of bytes.</param>
    /// <param name="mask">Mask for performing permutations.</param>
    /// <param name="lsbPosition">Specifies the order of bit numbering in bytes.</param>
    /// <param name="startingBitIndex">Specifies the index of the starting bit in the input bytes set.</param>
    /// <returns>Returns a set of bits with permuted values.</returns>
    public static Span<byte> Permutation(
        ReadOnlySpan<byte> bytes, 
        ReadOnlySpan<int> mask, 
        LeastSignificantBitPosition lsbPosition,
        StartingBitIndex startingBitIndex)
    {
        Span<byte> result = new byte[mask.Length/8];
        
        for (var i = 0; i < mask.Length; i++)
        {
            var targetIndex = mask[i] - (int)startingBitIndex;
            var bitValue = (bytes[targetIndex/8] >> (7 - targetIndex%8)) & 1;

            var byteIndex = i / 8;
            var bitIndex =
                lsbPosition == LeastSignificantBitPosition.Left ? 
                    7 - i % 8 : 
                    i % 8;
            
            result[byteIndex] &= (byte) ~(1 << bitIndex);
            result[byteIndex] |= (byte)(bitValue << bitIndex);
        }
        
        return result;
    }
}