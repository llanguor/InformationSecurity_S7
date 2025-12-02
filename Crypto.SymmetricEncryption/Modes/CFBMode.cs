using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

/// <summary>
/// Implements the Cipher Feedback (CFB) mode of operation for symmetric encryption.
/// Each plaintext block is XORed with the encryption of the previous ciphertext block
/// (or the initialization vector for the first block) to produce ciphertext.
/// Decryption reverses this process using the same mechanism, and asynchronous
/// versions are provided for parallel processing of blocks.
/// </summary>
public sealed class CFBMode(
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
            InitializationVector!
                .Value
                .ToArray()
                .AsMemory();
        
        for (var i = 0; i < data.Length; i+=BlockSize)
        {
            EncryptionFunc(lastBlock);
            
            var block = 
                data.Slice(i, BlockSize);
            
            for (var j = 0; j < BlockSize; ++j)
            {
                block.Span[j] ^= lastBlock.Span[j];
            }
            
            lastBlock = block.
                ToArray().
                AsMemory();
        }
    }

    /// <inheritdoc/>
    public override void Decrypt(Memory<byte> data)
    {
        var ciphers = data.ToArray().AsMemory();
        
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            ProcessDecryptBlock(data, ciphers, i);
        });
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
        var ciphers = data.ToArray().AsMemory();

        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                
                ProcessDecryptBlock(data, ciphers, i);
                
                return ValueTask.CompletedTask;
            });
    }

    /// <summary>
    /// Processes a single block during decryption by encrypting the previous
    /// ciphertext block (or the IV for the first block) and XORing the result
    /// with the current ciphertext block to recover the plaintext.
    /// </summary>
    private void ProcessDecryptBlock(
        Memory<byte> data, 
        Memory<byte> ciphers,
        int i)
    {
        var lastBlock =
            i==0?
                InitializationVector!.Value.ToArray():
                ciphers.Slice((i-1) * BlockSize, BlockSize);
            
        EncryptionFunc(lastBlock);
            
        var block = 
            data.Slice(i * BlockSize, BlockSize);
            
        for (var j = 0; j < BlockSize; ++j)
        {
            block.Span[j] ^= lastBlock.Span[j];
        }
    }
}