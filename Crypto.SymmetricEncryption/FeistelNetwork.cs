using System.Security.Cryptography;
using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Represents a Feistel network for symmetric block ciphers.
/// Provides in-place encryption and decryption of data using a configurable
/// <see cref="IKeySchedule"/> for round key generation and a <see cref="IRoundFunction"/> 
/// for the F-function applied in each round.
/// </summary>
public sealed class FeistelNetwork (
    IKeySchedule keySchedule, 
    IRoundFunction roundFunction,
    byte[] key,
    int roundsCount)
    : EncryptionBase(key)
{
    #region Fields
    
    /// <summary>
    /// The key schedule used to generate round keys from the master key.
    /// </summary>
    private readonly IKeySchedule _keySchedule = keySchedule;
    
    /// <summary>
    /// The round function (F-function) applied in each round of the Feistel network.
    /// </summary>
    private readonly IRoundFunction _roundFunction = roundFunction;

    /// <summary>
    /// Array of round keys generated from the master key.
    /// </summary>
    private byte[][] _roundKeys = keySchedule.Expand(key);

    /// <summary>
    /// Number of rounds in the Feistel network.
    /// </summary>
    private readonly int _roundsCount = roundsCount;
    
    #endregion
    
    
    #region Properties

    public override byte[] Key
    {
        get => base.Key;
        set
        {
            if (base.Key == value)
                return;
            
            _roundKeys = _keySchedule.Expand(value);
            base.Key = value;
        }
    }
    
    #endregion
    
    
    #region Methods

    /// <summary>
    /// Encrypts the specified data block using the Feistel network.
    /// The input <paramref name="data"/> is modified <c>in-place</c>.
    /// </summary>
    /// <param name="data">
    ///     The input block to encrypt.
    ///     Its length must be divisible by 2.
    /// </param>
    public override byte[] Encrypt(byte[] data)
    {
        //todo: check divisible by 2
        
        var half = data.Length / 2;
        var left = data[..half];
        var right = data[half..];
        Span<byte> buffer = stackalloc byte[half];
        
        for (var i = 0; i < _roundsCount-1; ++i)
        {
            left.CopyTo(buffer);
            right.CopyTo(left, 0);
            _roundFunction.TransformBlock(right, _roundKeys[i]);
            for (var b = 0; b < half; ++b)
            {
                right[b]^=buffer[b];
            }
        }

        left.CopyTo(buffer);
        right.CopyTo(left, 0);
        _roundFunction.TransformBlock(left, _roundKeys[_roundsCount-1]);
        for (var b = 0; b < half; ++b)
        {
            left[b]^=buffer[b];
        }
        
        left.CopyTo(data, 0);
        right.CopyTo(data, half);
        return data;
    }


    /// <summary>
    /// Decrypts the specified data block using the Feistel network.
    /// The input <paramref name="data"/> is modified <c>in-place</c>.
    /// </summary>
    /// <param name="data">
    ///     The input block to decrypt.
    ///     Its length must be divisible by 2.
    /// </param>
    public override byte[] Decrypt(byte[] data)
    {
        //todo: check divisible by 2

        var half = data.Length / 2;
        var left = data[..half];
        var right = data[half..];
        Span<byte> buffer = stackalloc byte[half];
        
        for (var i = _roundsCount-1; i > 0 ; --i)
        {
            left.CopyTo(buffer);
            right.CopyTo(left, 0);
            _roundFunction.TransformBlock(right, _roundKeys[i]);
            for (var b = 0; b < half; ++b)
            {
                right[b]^=buffer[b];
            }
        }

        left.CopyTo(buffer);
        right.CopyTo(left, 0);
        _roundFunction.TransformBlock(left, _roundKeys[0]);
        for (var b = 0; b < half; ++b)
        {
            left[b]^=buffer[b];
        }

        left.CopyTo(data, 0);
        right.CopyTo(data, half);
        return data;
    }
    
    #endregion
}