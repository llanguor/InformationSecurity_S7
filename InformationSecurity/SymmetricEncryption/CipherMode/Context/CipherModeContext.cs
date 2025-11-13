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
        Action<Memory<byte>> decryptionFunc,
        int blockSize,
        byte[]? initializationVector = null,
        params object[] parameters):
        base(encryptionFunc, decryptionFunc, blockSize, initializationVector, parameters)
    {
        if(mode != Enum.CipherMode.ECB &&
           initializationVector == null)
            throw new ArgumentException(null, nameof(initializationVector));

        _cipherMode = mode switch
        {
            Enum.CipherMode.ECB => 
                new ECBMode(encryptionFunc, decryptionFunc, blockSize),
            
            Enum.CipherMode.CBC => 
                new CBCMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            Enum.CipherMode.PCBC => 
                new PCBCMode(encryptionFunc,decryptionFunc,  blockSize, initializationVector!),
            
            Enum.CipherMode.CFB => 
                new CFBMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            Enum.CipherMode.OFB => 
                new OFBMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            Enum.CipherMode.CTR => 
                new CTRMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            Enum.CipherMode.RandomDelta => 
                new RandomDeltaMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
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

    public override async Task EncryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default)
    {
        await _cipherMode.EncryptAsync(data, cancellationToken);
    }

    public override async Task DecryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default)
    {
        await _cipherMode.DecryptAsync(data, cancellationToken);
    }
}