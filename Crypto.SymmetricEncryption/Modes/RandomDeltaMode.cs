using System.Numerics;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Modes;

public sealed class RandomDeltaMode(
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
        var delta
            = ComputeDelta();
        
        Parallel.For(0, data.Length / BlockSize, i =>
        {
            ProcessBlock(data, i, delta);
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
        var delta = 
            ComputeDelta();
        
        await Parallel.ForAsync(
            0,
            data.Length / BlockSize, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();
                ProcessBlock(data, i, delta);
                return ValueTask.CompletedTask;
            });
    }

    public override async Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default)
    {
        await EncryptAsync(data, cancellationToken);
    }

    private BigInteger ComputeDelta()
    {
        var span = 
            InitializationVector!
                .Value
                .Span[BlockSize..];
        
        var delta =
            new BigInteger(
                span, 
                isUnsigned: true, 
                isBigEndian: true) ;

        if ((delta & 1)==0)
            delta += 1;

        return delta;
    }

    private void ProcessBlock(Memory<byte> data, int i, BigInteger delta)
    {
        var value =
            new BigInteger(
                InitializationVector!.Value.Span,
                isUnsigned: true,
                isBigEndian: false);
        value += i*delta;
        
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