using System.Runtime.InteropServices;
using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Implementation of the <see cref="IKeySchedule"/> interface for the Crypto.Core.DES algorithm.
/// Responsible for generating 16 round keys from a 64-bit master key.
/// </summary>
public sealed class DESKeySchedule 
    : IKeySchedule
{
    #region Fields
    
    /// <summary>
    /// Permuted Choice 1 (PC-1) table used to permute the 64-bit master key into 56 bits.
    /// </summary>
    private static readonly int[] PermutedChoice1 = 
    [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    ];
    
    /// <summary>
    /// Permuted Choice 2 (PC-2) table used to generate each 48-bit round key from the 56-bit key halves.
    /// </summary>
    private static readonly int[] PermutedChoice2 = 
    [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ];
    
    /// <summary>
    /// Left-shifts for each round of key generation.
    /// </summary>
    private static readonly int[] Shifts =
    [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ];

    /// <summary>
    /// Number of Crypto.Core.DES rounds (16).
    /// </summary>
    private const int RoundsCount = 16;

    #endregion
    
    
    #region Methods

    /// <summary>
    /// Expands the specified 64-bit master key into 16 round keys of 48 bits each.
    /// </summary>
    /// <param name="key">
    ///     The master key as a read-only span of bytes. Must be exactly 8 bytes (64 bits) long.
    /// </param>
    /// <returns>
    /// An array of 16 round keys, each represented as a 6-byte array (48 bits).
    /// </returns>
    public byte[][] Expand(ReadOnlySpan<byte> key)
    {
        var roundKeys = 
            new byte[RoundsCount][];

        Span<byte> keySpan = stackalloc byte[8];
        Permutation.Permute(
            key,
            PermutedChoice1,
            keySpan,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Right);

        ref var ulongKey =
            ref MemoryMarshal.AsRef<ulong>(keySpan);

        for (var i = 0; i < RoundsCount; ++i)
        {
            var shift = Shifts[i];
            var mask = (1UL << shift) - 1;
            var lMask = mask << (64 - shift);
            var rMask = mask << (64 - 28 - shift);
            
            ulongKey = ((ulongKey & ~rMask) << shift)
                       | ((ulongKey & rMask) >> (28-shift))
                       | ((ulongKey & lMask) >> (28-shift));
            
            roundKeys[i] = new byte[6];
            Permutation.Permute(
                keySpan,
                PermutedChoice2,
                roundKeys[i],
                Permutation.StartingBitIndex.First,
                Permutation.LeastSignificantBitPosition.Right,
                Permutation.LeastSignificantBitPosition.Left);
        }
        
        return roundKeys;
    }
    
    #endregion
}