using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Implements the Data Encryption Standard (Crypto.Core.DES) symmetric encryption algorithm.
/// This class provides functionality for encrypting and decrypting 64-bit blocks of data.
/// </summary>
public sealed class DES(
    byte[] key, 
    CipherPadding padding, 
    CipherMode mode, 
    byte[]? initializationVector = null, 
    params object[] parameters)
    : SymmetricEncryption(8, key, padding, mode, initializationVector, parameters)
{
    #region Fields

    private const int FeistelRoundsCount = 16;
    
    /// <summary>
    /// The Crypto.Core.DES key schedule used to generate round keys.
    /// </summary>
    private static readonly IKeySchedule KeySchedule =
        new DESKeySchedule();
    
    /// <summary>
    /// The Crypto.Core.DES round function used in the Feistel network.
    /// </summary>
    private static readonly IRoundFunction RoundFunction =
        new DESRoundFunction();
    
    /// <summary>
    /// The internal Feistel network used for Crypto.Core.DES encryption and decryption.
    /// </summary>
    private readonly FeistelNetwork _feistelNetwork = 
        new (
            KeySchedule, 
            RoundFunction, 
            key, 
            FeistelRoundsCount);
    
    /// <summary>
    /// Initial permutation table (IP) for Crypto.Core.DES.
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
    /// Inverse of the initial permutation table (IP⁻¹) for Crypto.Core.DES.
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
    
    
    #region Properties

    /// <inherit/>
    public override byte[] Key
    {
        get => base.Key;
        set
        {
            if (base.Key == value)
                return;
            
            _feistelNetwork.Key = value;
            base.Key = value;
        }
    }

    #endregion
    
    
    #region Methods
    
    /// <inheritdoc/>
    internal override void EncryptBlock(Memory<byte> data)
    { 
        var buffer = new byte[BlockSize];
        Permutation.Permute(
            data.Span,
            InitialPermutation,
            buffer,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
        
        _feistelNetwork.Encrypt(buffer);
        
        Permutation.Permute(
            buffer,
            InverseInitialPermutation,
            data.Span,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
    }

    /// <inheritdoc/>
    internal override void DecryptBlock(Memory<byte> data)
    {
        var buffer = new byte[BlockSize];
        Permutation.Permute(
            data.Span,
            InitialPermutation,
            buffer,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
        
        _feistelNetwork.Decrypt(buffer);
        
        Permutation.Permute(
            buffer,
            InverseInitialPermutation,
            data.Span,
            Permutation.StartingBitIndex.First,
            Permutation.LeastSignificantBitPosition.Left,
            Permutation.LeastSignificantBitPosition.Left);
    }
    
    #endregion
}