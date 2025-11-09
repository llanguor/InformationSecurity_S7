using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

namespace InformationSecurity.SymmetricEncryption.DataEncryptionStandard;

/// <summary>
/// Implements the Data Encryption Standard (DES) symmetric encryption algorithm.
/// This class provides functionality for encrypting and decrypting 64-bit blocks of data.
/// </summary>
public sealed class DataEncryptionStandard(byte[] key)
    : IEncryption
{
    #region Fields
    
    /// <summary>
    /// The DES key schedule used to generate round keys.
    /// </summary>
    private static readonly IKeySchedule KeySchedule =
        new DesKeySchedule();
    
    /// <summary>
    /// The DES round function used in the Feistel network.
    /// </summary>
    private static readonly IRoundFunction RoundFunction =
        new DesRoundFunction();
    
    /// <summary>
    /// The internal Feistel network used for DES encryption and decryption.
    /// </summary>
    private readonly FeistelNetwork.FeistelNetwork _feistelNetwork = 
        new (
            KeySchedule, 
            RoundFunction, 
            key, 
            16);
    
    
    /// <summary>
    /// Initial permutation table (IP) for DES.
    /// </summary>
    private static readonly int[] InitialPermutation = 
    [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7 
    ];
    
    
    /// <summary>
    /// Inverse of the initial permutation table (IP⁻¹) for DES.
    /// </summary>
    private static readonly int[] InverseInitialPermutation = 
    [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29, 
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ];
    
    #endregion
    
    
    #region Methods
    
    /// <summary>
    /// Sets the master key for the DES cipher.
    /// The key is stored internally and used for subsequent encryption and decryption operations.
    /// </summary>
    /// <param name="key">
    /// The master key as a read-only span of bytes. 
    /// The key must be exactly 8 bytes (64 bits) long.
    /// </param>
    public void SetKey(ReadOnlySpan<byte> key)
    {
        _feistelNetwork.SetKey(key);
    }

    
    /// <summary>
    /// Encrypts a 64-bit block of data in-place using DES.
    /// </summary>
    /// <param name="data">
    /// The input block to encrypt. Must be exactly 8 bytes long.
    /// The block is modified in-place with the encrypted result.
    /// </param>
    public void Encrypt(Span<byte> data)
    {
        Span<byte> buffer = stackalloc byte[8];
        Permutation.Permute(
            data,
            InitialPermutation,
            buffer,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
        
        _feistelNetwork.Encrypt(buffer);
        
        Permutation.Permute(
            buffer,
            InverseInitialPermutation,
            data,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
    }

    /// <summary>
    /// Decrypts a 64-bit block of data in-place using DES.
    /// </summary>
    /// <param name="data">
    /// The input block to decrypt. Must be exactly 8 bytes long.
    /// The block is modified in-place with the decrypted result.
    /// </param>
    public void Decrypt(Span<byte> data)
    {
        Span<byte> buffer = stackalloc byte[data.Length];
        Permutation.Permute(
            data,
            InitialPermutation,
            buffer,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
        
        _feistelNetwork.Decrypt(buffer);
        
        Permutation.Permute(
            buffer,
            InverseInitialPermutation,
            data,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
    }
    
    #endregion
}