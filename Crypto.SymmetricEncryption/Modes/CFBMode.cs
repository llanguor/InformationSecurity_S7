using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

public sealed class CFBMode(
    Action<Memory<byte>> encryptionFunc,
    Action<Memory<byte>> decryptionFunc,
    int blockSize,
    Memory<byte> initializationVector)
    : CipherModeBase(
        encryptionFunc,
        decryptionFunc,
        blockSize,
        initializationVector)
{
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

    public override void Decrypt(Memory<byte> data)
    {
        var ciphers = data.ToArray().AsMemory();
        
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            ProcessDecryptBlock(data, ciphers, i);
        });
    }

    public override async Task EncryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        await Task.Run(() => Encrypt(data), cancellationToken);
    }

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