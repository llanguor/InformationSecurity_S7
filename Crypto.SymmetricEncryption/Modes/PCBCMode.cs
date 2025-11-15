using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

public sealed class PCBCMode(
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