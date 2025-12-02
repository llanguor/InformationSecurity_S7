using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

/// <summary>
/// Implements the Electronic Codebook (ECB) mode of operation for symmetric encryption.
/// Each block is encrypted or decrypted independently, without chaining,
/// making ECB parallelizable but susceptible to pattern leakage.
/// </summary>
public sealed class ECBMode(
    Action<Memory<byte>> encryptionFunc,
    Action<Memory<byte>> decryptionFunc,
    int blockSize)
    : SymmetricModeBase(
        encryptionFunc,
        decryptionFunc,
        blockSize)
{  
    /// <inheritdoc/>
    public override void Encrypt(Memory<byte> data)
    {
        ThrowIfIncorrectInputData(data);
        
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            EncryptionFunc(
                data.Slice(i * BlockSize, BlockSize));
        });
    }

    /// <inheritdoc/>
    public override void Decrypt(Memory<byte> data)
    {
        ThrowIfIncorrectInputData(data);
        
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            DecryptionFunc(
                data.Slice(i * BlockSize, BlockSize));
        });
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        ThrowIfIncorrectInputData(data);
        
        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                EncryptionFunc(data.Slice(i * BlockSize, BlockSize));
                return ValueTask.CompletedTask;
            });
    }
    
    /// <inheritdoc/>
    public override async Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        ThrowIfIncorrectInputData(data);
        
        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                DecryptionFunc(data.Slice(i * BlockSize, BlockSize));
                return ValueTask.CompletedTask;
            });
    }
}