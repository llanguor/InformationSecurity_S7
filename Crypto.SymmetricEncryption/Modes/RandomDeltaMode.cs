using System.Numerics;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

/// <summary>
/// Implements a stream-like block mode where each block is XORed with a
/// pseudo-random value derived from the initialization vector and a delta.
/// The delta is computed from the IV and enforced to be odd, ensuring that
/// each block uses a unique, non-repeating offset. Encryption and decryption
/// are identical operations.
/// </summary>
public sealed class RandomDeltaMode(
    Action<Memory<byte>> encryptionFunc,
    Action<Memory<byte>> decryptionFunc,
    int blockSize,
    Memory<byte> initializationVector)
    : SymmetricModeBase(
        encryptionFunc,
        decryptionFunc,
        blockSize,
        initializationVector)
{
    /// <inheritdoc/>
    public override void Encrypt(Memory<byte> data)
    {
        var delta
            = ComputeDelta();
        
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            ProcessBlock(data, i, delta);
        });
    }

    /// <inheritdoc/>
    public override void Decrypt(Memory<byte> data)
    {
        Encrypt(data);
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        var delta = 
            ComputeDelta();
        
        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                ProcessBlock(data, i, delta);
                return ValueTask.CompletedTask;
            });
    }
    
    /// <inheritdoc/>
    public override async Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        await EncryptAsync(data, cancellationToken);
    }

    /// <summary>
    /// Computes the delta value used to generate unique offsets for each block.
    /// The delta is derived from the second half of the IV and forced to be odd.
    /// </summary>
    private BigInteger ComputeDelta()
    {
        var span = 
            InitializationVector!
                .Value
                .Span[BlockSize..];
        
        var delta =
            new BigInteger(
                span, 
                isUnsigned: true, 
                isBigEndian: true) ;

        if ((delta & 1)==0)
            delta += 1;

        return delta;
    }

    /// <summary>
    /// Applies the delta-based transformation to a single block:
    /// computes the offset for the block, encrypts it,
    /// and XORs the result with the plaintext block.
    /// </summary>
    private void ProcessBlock(Memory<byte> data, int i, BigInteger delta)
    {
        var value =
            new BigInteger(
                InitializationVector!.Value.Span,
                isUnsigned: true,
                isBigEndian: false);
        value += i*delta;
        
        var valueByte = new byte[BlockSize];
        if (!value.TryWriteBytes(valueByte, out int _, isUnsigned: true, isBigEndian: false))
        {
            throw new InvalidOperationException("Incorrect input size of block");
        }
        EncryptionFunc(valueByte);
        
        var block = 
            data.Slice(i * BlockSize, BlockSize);
        
        for (var j = 0; j < BlockSize; ++j)
        {
            block.Span[j] ^= valueByte[j];
        }
    }
}