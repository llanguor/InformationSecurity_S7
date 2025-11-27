using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

public class OFBMode(
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
    public override void Encrypt(Memory<byte> data)
    {
        var iv =
            InitializationVector!
                .Value
                .ToArray();
        
        for (var i = 0; i < data.Length; i+=BlockSize)
        {
            EncryptionFunc(iv);
            
            var block = 
                data.Slice(i, BlockSize);
            
            for (var j = 0; j < BlockSize; ++j)
            {
                block.Span[j] ^= iv[j];
            }
        }
    }

    public override void Decrypt(Memory<byte> data)
    {
        Encrypt(data);
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
        await Task.Run(() => Decrypt(data), cancellationToken);
    }
}