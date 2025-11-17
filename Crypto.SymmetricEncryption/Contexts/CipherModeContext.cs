using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Modes;

namespace Crypto.SymmetricEncryption.Contexts;

public sealed class CipherModeContext : 
    CipherModeBase
{
    #region Fields
    
    private readonly ICipherMode _cipherMode;
    
    #endregion
    
    
    #region Constructors
    
    public CipherModeContext(
        CipherModes modes,
        Action<Memory<byte>> encryptionFunc,
        Action<Memory<byte>> decryptionFunc,
        int blockSize,
        byte[]? initializationVector = null,
        params object[] parameters):
        base(encryptionFunc, decryptionFunc, blockSize, initializationVector, parameters)
    {
        if(modes != CipherModes.ECB &&
           initializationVector == null)
            throw new ArgumentException(null, nameof(initializationVector));

        _cipherMode = modes switch
        {
            CipherModes.ECB => 
                new ECBMode(encryptionFunc, decryptionFunc, blockSize),
            
            CipherModes.CBC => 
                new CBCMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            CipherModes.PCBC => 
                new PCBCMode(encryptionFunc,decryptionFunc,  blockSize, initializationVector!),
            
            CipherModes.CFB => 
                new CFBMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            CipherModes.OFB => 
                new OFBMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            CipherModes.CTR => 
                new CTRMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            CipherModes.RandomDelta => 
                new RandomDeltaMode(encryptionFunc, decryptionFunc, blockSize, initializationVector!),
            
            _ => throw new ArgumentOutOfRangeException(nameof(modes), modes, null)
        };
    }
    
    #endregion
    
    
    #region Methods

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
    
    #endregion
}