using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Modes;

public sealed class CbcMode (
    Action<Memory<byte>> encryptionFunc,
    Action<Memory<byte>> decryptionFunc,
    int blockSize,
    byte[] initializationVector)
    : CipherModeBase(
        encryptionFunc,
        decryptionFunc,
        blockSize,
        initializationVector)
{
    public override void Encrypt(Memory<byte> data)
    {
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

    public override void Decrypt(Memory<byte> data)
    {
        var ciphers = 
            data.ToArray().AsMemory();
        
        Parallel.For(0, data.Length / BlockSize, i =>
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
        var ciphers = 
            data.ToArray().AsMemory();
        
        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                
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
                
                return ValueTask.CompletedTask;
            });
    }
}