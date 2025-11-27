using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

public sealed class ECBMode(
    Action<Memory<byte>> encryptionFunc,
    Action<Memory<byte>> decryptionFunc,
    int blockSize)
    : SymmetricModeBase(
        encryptionFunc,
        decryptionFunc,
        blockSize)
{
    public override void Encrypt(Memory<byte> data)
    {
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            EncryptionFunc(
                data.Slice(i * BlockSize, BlockSize));
        });
    }

    public override void Decrypt(Memory<byte> data)
    {
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            DecryptionFunc(
                data.Slice(i * BlockSize, BlockSize));
        });
    }

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
                EncryptionFunc(data.Slice(i * BlockSize, BlockSize));
                return ValueTask.CompletedTask;
            });
    }
    
    public override async Task DecryptAsync(
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
                DecryptionFunc(data.Slice(i * BlockSize, BlockSize));
                return ValueTask.CompletedTask;
            });
    }
}