using System.Numerics;
using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Modes;

public sealed class CTRMode(
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
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            ProcessEncryptBlock(data, i);
        });
    }

    public override void Decrypt(Memory<byte> data)
    {
        Encrypt(data);
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
                ProcessEncryptBlock(data, i);
                return ValueTask.CompletedTask;
            });
    }

    public override async Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        await EncryptAsync(data, cancellationToken);
    }
    
    private void ProcessEncryptBlock(Memory<byte> data, int i)
    {
        var value =
            new BigInteger(
                InitializationVector!.Value.Span,
                isUnsigned: true,
                isBigEndian: false)
            + i;
        
        var valueByte = new byte[BlockSize];
        if (!value.TryWriteBytes(valueByte, out int _, isUnsigned: true, isBigEndian: false))
        {
            throw new InvalidOperationException("Incorrect input size of block");
        }
        EncryptionFunc(valueByte);
        
        var block = 
            data.Slice(i * BlockSize, BlockSize);
        
        for (var j = 0; j < BlockSize; ++j)
        {
            block.Span[j] ^= valueByte[j];
        }
    }
}