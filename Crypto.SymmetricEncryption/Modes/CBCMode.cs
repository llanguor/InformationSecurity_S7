using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

/// <summary>
/// Implements the Cipher Block Chaining (CBC) mode of operation for symmetric encryption.
/// Applies XOR with the previous ciphertext block (or the initialization vector for the first block)
/// before encryption, and reverses the process during decryption.
/// </summary>
public sealed class CBCMode : 
    SymmetricModeBase
{
    /// <summary>
    /// Implements the Cipher Block Chaining (CBC) mode of operation for symmetric encryption.
    /// Applies XOR with the previous ciphertext block (or the initialization vector for the first block)
    /// before encryption, and reverses the process during decryption.
    /// </summary>
    public CBCMode(Action<Memory<byte>> encryptionFunc,
        Action<Memory<byte>> decryptionFunc,
        int blockSize,
        Memory<byte> initializationVector) :
        base(encryptionFunc,
        decryptionFunc,
        blockSize,
        initializationVector)
    {
        ThrowIfInitializationVectorIsNull();
    }

    /// <inheritdoc/>   
    public override void Encrypt(Memory<byte> data)
    {
        ThrowIfIncorrectInputData(data);
        
        var lastBlock =
            InitializationVector!.Value;
        
        for (var i = 0; i < data.Length; i+=BlockSize)
        {
            var block = 
                data.Slice(i, BlockSize);
            
            for (var j = 0; j < BlockSize; ++j)
            {
                block.Span[j] ^= lastBlock.Span[j];
            }
            
            EncryptionFunc(block);
            lastBlock = block;
        }
    }

    /// <inheritdoc/>   
    public override void Decrypt(Memory<byte> data)
    {
        ThrowIfIncorrectInputData(data);
        
        var ciphers = 
            data.ToArray().AsMemory();
        
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
        ThrowIfIncorrectInputData(data);
        await Task.Run(() => Encrypt(data), cancellationToken);
    }

    /// <inheritdoc/>   
    public override async Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        ThrowIfIncorrectInputData(data);
        
        var ciphers = 
            data.ToArray().AsMemory();
        
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
    /// Processes a single block during decryption by applying the F-function
    /// to the previous ciphertext block (or IV for the first block) and XORing
    /// the result with the current ciphertext block to recover plaintext.
    /// </summary>
    private void ProcessDecryptBlock(Memory<byte> data, Memory<byte> ciphers, int i)
    {
        var lastBlock =
            i==0?
                InitializationVector!.Value:
                ciphers.Slice((i-1) * BlockSize, BlockSize);
            
        var block = 
            data.Slice(i * BlockSize, BlockSize);
            
        DecryptionFunc(block);
            
        for (var j = 0; j < BlockSize; ++j)
        {
            block.Span[j] ^= lastBlock.Span[j];
        }
    }
    


}