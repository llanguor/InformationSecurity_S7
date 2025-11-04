using InformationSecurity_Tests.Infrastructure;
using InformationSecurity.SymmetricEncryption;
using Serilog;

namespace InformationSecurity_Tests;

public class Tests
{
    [SetUp]
    public void Setup()
    {
    }
    
    [Test]
    public void PermutationsTest()
    {
        Span<byte> values = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b01101010,0b10011110
        ];
        
        Span<int> mask = 
        [
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
        ];
        
        Span<byte> expectedResult = 
        [
            0b10010100,0b01101011,0b01011111,0b10001111,
            0b11101001,0b10111101,0b11110010,0b00000000
        ];

        var result =
            PermutationSubstitution.Permute(
                values,
                mask,
                PermutationSubstitution.StartingBitIndex.First,
                PermutationSubstitution.LeastSignificantBitPosition.Left,
                PermutationSubstitution.LeastSignificantBitPosition.Left);
        
        Log.Information(
            $"Permutation Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            result.ToArray(), 
            expectedResult.ToArray());
    }
}