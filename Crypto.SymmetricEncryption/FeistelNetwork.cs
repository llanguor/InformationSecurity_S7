using System.Security.Cryptography;
using Crypto.Core;
using Crypto.Core.Base.Interfaces;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Represents a Feistel network for symmetric block ciphers.
/// Provides in-place encryption and decryption of data using a configurable
/// <see cref="IKeySchedule"/> for round key generation and a <see cref="IRoundFunction"/> 
/// for the F-function applied in each round.
/// </summary>
public sealed class FeistelNetwork : 
    IEncryption
{
    #region Constructors

    /// <summary>
    /// Represents a Feistel network for symmetric block ciphers.
    /// Provides in-place encryption and decryption of data using a configurable
    /// <see cref="IKeySchedule"/> for round key generation and a <see cref="IRoundFunction"/> 
    /// for the F-function applied in each round.
    /// </summary>
    public FeistelNetwork(
        IKeySchedule keySchedule, 
        IRoundFunction roundFunction,
        byte[] key,
        int roundsCount)
    {
        if (roundsCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(roundsCount), "Rounds count must be positive.");
        
        _key = key ?? throw new ArgumentNullException(nameof(key));
        _keySchedule = keySchedule ?? throw new ArgumentNullException(nameof(keySchedule));
        _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
        _roundKeys = keySchedule.Expand(key);
        _roundsCount = roundsCount;
    }
    
    #endregion

    
    #region Fields
    
    /// <summary>
    /// The master key used as the base material for generating all round keys.
    /// </summary>
    private byte[] _key;
    
    /// <summary>
    /// The key schedule used to generate round keys from the master key.
    /// </summary>
    private readonly IKeySchedule _keySchedule;
    
    /// <summary>
    /// The round function (F-function) applied in each round of the Feistel network.
    /// </summary>
    private readonly IRoundFunction _roundFunction;

    /// <summary>
    /// Array of round keys generated from the master key.
    /// </summary>
    private byte[][] _roundKeys;

    /// <summary>
    /// Number of rounds in the Feistel network.
    /// </summary>
    private readonly int _roundsCount;

    #endregion
    
    
    #region Properties

    /// <summary>
    /// Gets or sets the master key used for round key generation.
    /// Updating the key triggers regeneration of all round keys.
    /// </summary>
    public byte[] Key
    {
        get => _key;
        set
        {
            if(_key == null)
                throw new ArgumentNullException(nameof(value), "Key cannot be null."); 

            if (_key == value)
                return;

            _roundKeys = _keySchedule.Expand(value);
            _key = value;
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
    public Memory<byte> Encrypt(Memory<byte> data)
    {
        if (data.IsEmpty || (data.Length & 1) != 0)
        {
            throw new ArgumentException(
                "Data length must be divisible by 2.", 
                nameof(data));
        }
        
        var half = data.Length / 2;
        var left = data[..half];
        var right = data[half..];
        Span<byte> buffer = stackalloc byte[half];
        
        for (var i = 0; i < _roundsCount-1; ++i)
        {
            left.Span.CopyTo(buffer);
            right.CopyTo(left);
            _roundFunction.TransformBlock(right, _roundKeys[i]);
            for (var b = 0; b < half; ++b)
            {
                right.Span[b]^=buffer[b];
            }
        }

        left.Span.CopyTo(buffer);
        right.CopyTo(left);
        _roundFunction.TransformBlock(left, _roundKeys[_roundsCount-1]);
        for (var b = 0; b < half; ++b)
        {
            left.Span[b]^=buffer[b];
        }

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
    public Memory<byte> Decrypt(Memory<byte> data)
    {
        if (data.IsEmpty || (data.Length & 1) != 0)
        {
            throw new ArgumentException(
                "Data length must be divisible by 2.", 
                nameof(data));
        }

        var half = data.Length / 2;
        var left = data[..half];
        var right = data[half..];
        Span<byte> buffer = stackalloc byte[half];
        
        for (var i = _roundsCount-1; i > 0 ; --i)
        {
            left.Span.CopyTo(buffer);
            right.CopyTo(left);
            _roundFunction.TransformBlock(right, _roundKeys[i]);
            for (var b = 0; b < half; ++b)
            {
                right.Span[b]^=buffer[b];
            }
        }

        left.Span.CopyTo(buffer);
        right.CopyTo(left);
        _roundFunction.TransformBlock(left, _roundKeys[0]);
        for (var b = 0; b < half; ++b)
        {
            left.Span[b]^=buffer[b];
        }

        return data;
    }
    
    #endregion
}