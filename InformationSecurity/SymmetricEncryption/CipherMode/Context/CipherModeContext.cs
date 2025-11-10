using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Modes;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Context;

public sealed class CipherModeContext : CipherModeBase
{
    private readonly ICipherMode _cipherMode;
    
    public CipherModeContext(
        Enum.CipherMode mode,
        byte[]? initializationVector = null,
        object[]? parameters = null)
    {
        if(mode != Enum.CipherMode.Ecb &&
           initializationVector == null)
            throw new ArgumentException(null, nameof(initializationVector));

        _cipherMode = mode switch
        {
            Enum.CipherMode.Ecb => new Ecb(),
            Enum.CipherMode.Cbc => new Cbc(initializationVector!),
            Enum.CipherMode.Pcbc => new Pcbc(initializationVector!),
            Enum.CipherMode.Cfb => new Cfb(initializationVector!),
            Enum.CipherMode.Ofb => new Ofb(initializationVector!),
            Enum.CipherMode.Ctr => new Ctr(initializationVector!),
            Enum.CipherMode.RandomDelta => new RandomDelta(initializationVector!),
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null)
        };
    }

    public override void Encrypt(Span<byte> data, IEncryption encryption, int blockSize)
    {
        _cipherMode.Encrypt(data, encryption, blockSize);
    }

    public override void Decrypt(Span<byte> data, IEncryption encryption, int blockSize)
    {
        _cipherMode.Decrypt(data, encryption, blockSize);
    }

    public override async Task EncryptAsync(Memory<byte> data, IEncryption encryption, int blockSize)
    {
        await _cipherMode.EncryptAsync(data, encryption, blockSize);
    }

    public override async Task DecryptAsync(Memory<byte> data, IEncryption encryption, int blockSize)
    {
        await _cipherMode.DecryptAsync(data, encryption, blockSize);
    }
}