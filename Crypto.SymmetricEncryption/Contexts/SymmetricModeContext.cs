using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Modes;

namespace Crypto.SymmetricEncryption.Contexts;

public sealed class SymmetricModeContext : 
    SymmetricModeBase
{
    #region Fields
    
    private ISymmetricMode _modeAlgorithm = null!;
    
    private SymmetricMode _mode;
    
    #endregion
    
    
    #region Properties

    public SymmetricMode Mode
    {
        get => _mode;
        set
        {
            _mode = value;
            _modeAlgorithm = value switch
            {
                SymmetricMode.ECB => 
                    new ECBMode(EncryptionFunc, DecryptionFunc, BlockSize),
            
                SymmetricMode.CBC => 
                    new CBCMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                SymmetricMode.PCBC => 
                    new PCBCMode(EncryptionFunc,DecryptionFunc,  BlockSize, InitializationVector!.Value),
            
                SymmetricMode.CFB => 
                    new CFBMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                SymmetricMode.OFB => 
                    new OFBMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                SymmetricMode.CTR => 
                    new CTRMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value),
            
                SymmetricMode.RandomDelta => 
                    new RandomDeltaMode(EncryptionFunc, DecryptionFunc, BlockSize, InitializationVector!.Value!),
            
                _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
            };
        }
    }
    
    #endregion
    
    
    #region Enumerations
    
    /// <summary>
    /// Defines the supported block cipher modes for symmetric encryption.
    /// </summary>
    public enum SymmetricMode
    {
        ECB = 0,
        CBC = 1,
        PCBC = 2,
        CFB = 3,
        OFB = 4,
        CTR = 5,
        RandomDelta = 6
    }
    
    #endregion

    
    #region Constructors
    
    public SymmetricModeContext(
        SymmetricMode mode,
        Action<Memory<byte>> encryptionFunc,
        Action<Memory<byte>> decryptionFunc,
        int blockSize,
        byte[]? initializationVector = null,
        params object[] parameters):
        base(encryptionFunc, decryptionFunc, blockSize, initializationVector, parameters)
    {
        if(mode != SymmetricMode.ECB &&
           initializationVector == null)
            throw new ArgumentException(null, nameof(initializationVector));
        
        Mode = mode;
    }
    
    #endregion
    
    
    #region Methods

    public override void Encrypt(Memory<byte> data)
    {
        _modeAlgorithm.Encrypt(data);
    }

    public override void Decrypt(Memory<byte> data)
    {
        _modeAlgorithm.Decrypt(data);
    }

    public override async Task EncryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default)
    {
        await _modeAlgorithm.EncryptAsync(data, cancellationToken);
    }

    public override async Task DecryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default)
    {
        await _modeAlgorithm.DecryptAsync(data, cancellationToken);
    }
    
    #endregion
}