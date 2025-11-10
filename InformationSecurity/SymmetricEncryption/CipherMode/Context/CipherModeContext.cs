using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Modes;
namespace InformationSecurity.SymmetricEncryption.CipherMode.Context;

public sealed class CipherModeContext : CipherModeBase
{
    private readonly ICipherMode _cipherMode;
    
    public CipherModeContext(
        Enum.CipherMode mode,
        Action<Memory<byte>> encryptionFunc,
        int blockSize,
        byte[]? initializationVector = null,
        params object[] parameters):
        base(encryptionFunc, blockSize, initializationVector, parameters)
    {
        if(mode != Enum.CipherMode.Ecb &&
           initializationVector == null)
            throw new ArgumentException(null, nameof(initializationVector));

        _cipherMode = mode switch
        {
            Enum.CipherMode.Ecb => new EcbMode(encryptionFunc, blockSize),
            Enum.CipherMode.Cbc => new CbcMode(encryptionFunc, blockSize, initializationVector!),
            Enum.CipherMode.Pcbc => new PcbcMode(encryptionFunc, blockSize, initializationVector!),
            Enum.CipherMode.Cfb => new CfbMode(encryptionFunc, blockSize, initializationVector!),
            Enum.CipherMode.Ofb => new OfbMode(encryptionFunc, blockSize, initializationVector!),
            Enum.CipherMode.Ctr => new CtrMode(encryptionFunc, blockSize, initializationVector!),
            Enum.CipherMode.RandomDelta => new RandomDeltaMode(encryptionFunc, blockSize, initializationVector!),
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null)
        };
    }

    public override void Encrypt(Memory<byte> data)
    {
        _cipherMode.Encrypt(data);
    }

    public override void Decrypt(Memory<byte> data)
    {
        _cipherMode.Decrypt(data);
    }

    public override async Task EncryptAsync(Memory<byte> data)
    {
        await _cipherMode.EncryptAsync(data);
    }

    public override async Task DecryptAsync(Memory<byte> data)
    {
        await _cipherMode.DecryptAsync(data);
    }
}