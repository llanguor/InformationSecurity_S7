using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

/// <summary>
/// Implements the Propagating Cipher Block Chaining (PCBC) mode of operation for symmetric encryption.
/// Each plaintext block is XORed with the previous ciphertext block and the previous plaintext block
/// before encryption. Decryption reverses this process, propagating changes across all subsequent blocks.
/// </summary>
public sealed class PCBCMode(
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
        var lastBlock =
            InitializationVector!.Value;
        
        byte[]? lastPlainText = null;

        for (var i = 0; i < data.Length; i+=BlockSize)
        {
            var block = 
                data.Slice(i, BlockSize);
            
            var currentPlainText = block.ToArray();
            
            for (var j = 0; j < BlockSize; ++j)
            {
                block.Span[j] ^= lastBlock.Span[j];
            }

            if (i >= BlockSize)
            {
                for (var j = 0; j < BlockSize; ++j)
                {
                    block.Span[j] ^= lastPlainText![j];
                }
            }
            
            EncryptionFunc(block);
            lastBlock = block;
            lastPlainText = currentPlainText.ToArray();
        }
    }

    /// <inheritdoc/>
    public override void Decrypt(Memory<byte> data)
    {
        var lastBlock =
            InitializationVector!.Value.ToArray().AsSpan();
        Span<byte> lastPlainText = null;

        for (var i = 0; i < data.Length ; i+=BlockSize)
        {
            var block = 
                data.Slice(i, BlockSize);
           
            var currentCipherText = block.ToArray();
            DecryptionFunc(block);
            
            for (var j = 0; j < BlockSize; ++j)
            {
                block.Span[j] ^= lastBlock[j];
            }

            if (i >= BlockSize)
            {
                for (var j = 0; j < BlockSize; ++j)
                {
                    block.Span[j] ^= lastPlainText[j];
                }
            }
            
            lastBlock = currentCipherText.ToArray();
            lastPlainText = block.Span;
        }
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        await Task.Run(() => Encrypt(data), cancellationToken);
    }

    /// <inheritdoc/>
    public override async Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        await Task.Run(() => Decrypt(data), cancellationToken);
    }
}