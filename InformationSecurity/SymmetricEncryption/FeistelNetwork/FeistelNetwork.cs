using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;
namespace InformationSecurity.SymmetricEncryption.FeistelNetwork;

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
    : IEncryption
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
    
    
    #region Methods
    
    /// <summary>
    /// Sets the master key for the Feistel network and regenerates round keys.
    /// </summary>
    /// <param name="key">
    ///     The master key as a <see cref="ReadOnlySpan{Byte}"/>. 
    /// </param>
    public void SetKey(byte[] key)
    {
        _roundKeys = _keySchedule.Expand(key);
    }

    /// <summary>
    /// Encrypts the specified data block using the Feistel network.
    /// The input <paramref name="data"/> is modified <c>in-place</c>.
    /// </summary>
    /// <param name="data">
    ///     The input block to encrypt.
    ///     Its length must be divisible by 2, as the block is split into left and right halves.
    /// </param>
    public byte[] Encrypt(byte[] data)
    {
        Encrypt(data.AsSpan());
        return data;
    }

    /// <summary>
    /// Decrypts the specified data block using the Feistel network.
    /// The input <paramref name="data"/> is modified <c>in-place</c>.
    /// </summary>
    /// <param name="data">
    ///     The input block to decrypt.
    ///     Its length must be divisible by 2, as the block is split into left and right halves.
    /// </param>
    public byte[] Decrypt(byte[] data)
    {
        Decrypt(data.AsSpan());
        return data;
    }

    /// <summary>
    /// Encrypts the specified data block using the Feistel network.
    /// The input <paramref name="data"/> is modified <c>in-place</c>.
    /// </summary>
    /// <param name="data">
    ///     The input block to encrypt as a <see cref="Span{Byte}"/>.
    ///     Its length must be divisible by 2, as the block is split into left and right halves.
    /// </param>
    public void Encrypt(Span<byte> data)
    {
        var half = data.Length / 2;
        Span<byte> buffer = stackalloc byte[half];
        var left = data[..half];
        var right = data[half..];
        
        for (var i = 0; i < _roundsCount-1; ++i)
        {
            left.CopyTo(buffer);
            right.CopyTo(left);
            _roundFunction.TransformBlock(right, _roundKeys[i]);
            for (var b = 0; b < half; ++b)
            {
                right[b]^=buffer[b];
            }
        }

        left.CopyTo(buffer);
        right.CopyTo(left);
        _roundFunction.TransformBlock(left, _roundKeys[_roundsCount-1]);
        for (var b = 0; b < half; ++b)
        {
            left[b]^=buffer[b];
        }
    }

    /// <summary>
    /// Decrypts the specified data block using the Feistel network.
    /// The input <paramref name="data"/> is modified <c>in-place</c>.
    /// </summary>
    /// <param name="data">
    ///     The input block to decrypt as a <see cref="Span{Byte}"/>.
    ///     Its length must be divisible by 2, as the block is split into left and right halves.
    /// </param>
    public void Decrypt(Span<byte> data)
    {
        var half = data.Length / 2;
        Span<byte> buffer = stackalloc byte[half];
        var left = data[..half];
        var right = data[half..];
        
        for (var i = _roundsCount-1; i > 0 ; --i)
        {
            left.CopyTo(buffer);
            right.CopyTo(left);
            _roundFunction.TransformBlock(right, _roundKeys[i]);
            for (var b = 0; b < half; ++b)
            {
                right[b]^=buffer[b];
            }
        }

        left.CopyTo(buffer);
        right.CopyTo(left);
        _roundFunction.TransformBlock(left, _roundKeys[0]);
        for (var b = 0; b < half; ++b)
        {
            left[b]^=buffer[b];
        }
    }
    
    #endregion
}