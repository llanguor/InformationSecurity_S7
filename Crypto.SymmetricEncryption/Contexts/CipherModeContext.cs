using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Modes;

namespace Crypto.SymmetricEncryption.Contexts;

public sealed class CipherModeContext : 
    CipherModeBase
{
    #region Fields
    
    private ICipherMode _cipherMode = null!;
    
    private CipherMode _cipherModeType;
    
    #endregion
    
    
    #region Properties

    public CipherMode CipherModeType
    {
        get => _cipherModeType;
        set
        {
            _cipherModeType = value;
            _cipherMode = value switch
            {
                CipherMode.ECB => 
                    new ECBMode(EncryptionFunc, DecryptionFunc, BlockSize),
            
                CipherMode.CBC => 
                    new CBCMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                CipherMode.PCBC => 
                    new PCBCMode(EncryptionFunc,DecryptionFunc,  BlockSize, InitializationVector!.Value),
            
                CipherMode.CFB => 
                    new CFBMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                CipherMode.OFB => 
                    new OFBMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                CipherMode.CTR => 
                    new CTRMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                CipherMode.RandomDelta => 
                    new RandomDeltaMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value!),
            
                _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
            };
        }
    }
    
    #endregion
    
    
    #region Constructors
    
    public CipherModeContext(
        CipherMode mode,
        Action<Memory<byte>> encryptionFunc,
        Action<Memory<byte>> decryptionFunc,
        int blockSize,
        byte[]? initializationVector = null,
        params object[] parameters):
        base(encryptionFunc, decryptionFunc, blockSize, initializationVector, parameters)
    {
        if(mode != CipherMode.ECB &&
           initializationVector == null)
            throw new ArgumentException(null, nameof(initializationVector));
        
        CipherModeType = mode;
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