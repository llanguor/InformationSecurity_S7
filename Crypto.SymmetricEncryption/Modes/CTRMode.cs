using System.Numerics;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

/// <summary>
/// Implements the Counter (CTR) mode of operation for symmetric encryption.
/// Each block is XORed with the encryption of a counter value derived from
/// the initialization vector and the block index. Encryption and decryption
/// are identical operations.
/// </summary
public sealed class CTRMode(
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
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            ProcessEncryptBlock(data, i);
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
        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                ProcessEncryptBlock(data, i);
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
    /// Processes a single block by computing its counter value from the IV and block index,
    /// encrypting the counter, and XORing the result with the plaintext block.
    /// </summary>
    private void ProcessEncryptBlock(Memory<byte> data, int i)
    {
        var value =
            new BigInteger(
                InitializationVector!.Value.Span,
                isUnsigned: true,
                isBigEndian: false)
            + i;
        
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