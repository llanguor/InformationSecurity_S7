using System.Runtime.InteropServices;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;
namespace InformationSecurity.SymmetricEncryption.DataEncryptionStandard;

/// <summary>
/// Implementation of the <see cref="IKeySchedule"/> interface for the DES algorithm.
/// Responsible for generating round keys from the original key.
/// </summary>
public sealed class DesKeySchedule 
    : IKeySchedule
{
    private static readonly int[] PermutedChoice1 = 
    [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    ];
    
    private static readonly int[] PermutedChoice2 = 
    [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ];
    
    private static readonly int[] Shifts =
    [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ];

    private static readonly int RoundsCount = 16;
    
    /// <inheritdoc/>
    public byte[][] Expand(byte[] key)
    {
        var roundKeys = 
            new byte[RoundsCount][];
        
        var keySpan = PermutationSubstitution.Permute(
            key,
            PermutedChoice1,
            PermutationSubstitution.StartingBitIndex.First,
            PermutationSubstitution.LeastSignificantBitPosition.Left,
            PermutationSubstitution.LeastSignificantBitPosition.Right);
        
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
            
            roundKeys[i] = PermutationSubstitution.Permute(
                    keySpan,
                    PermutedChoice2,
                    PermutationSubstitution.StartingBitIndex.First,
                    PermutationSubstitution.LeastSignificantBitPosition.Right,
                    PermutationSubstitution.LeastSignificantBitPosition.Left)
                    .ToArray();
        }
        
        return roundKeys;
    }
}