using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Modes;

public sealed class CfbMode(
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
        var iv = ComputeEncryptIv();

        Parallel.For(0, data.Length / BlockSize, i =>
        {
            ProcessDecryptBlock(data, ciphers, iv, i);
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
        var iv = ComputeEncryptIv();
        
        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                ProcessDecryptBlock(data, ciphers, iv, i);
                return ValueTask.CompletedTask;
            });
    }

    private byte[] ComputeEncryptIv()
    {
        var iv = InitializationVector!.Value.ToArray();
        EncryptionFunc(iv);
        return iv;
    }

    private void ProcessDecryptBlock(
        Memory<byte> data, 
        Memory<byte> ciphers,
        byte[] iv, 
        int i)
    {
        var lastBlock =
            i==0?
                iv:
                ciphers.Slice((i-1) * BlockSize, BlockSize);
            
        var block = 
            data.Slice(i * BlockSize, BlockSize);
            
        for (var j = 0; j < BlockSize; ++j)
        {
            block.Span[j] ^= lastBlock.Span[j];
        }
    }
}