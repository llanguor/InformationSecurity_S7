using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Contexts;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Implementation of the DEAL (Data Encryption Algorithm with Large blocks) symmetric encryption algorithm.
/// Uses a Feistel network with configurable key sizes and DES-based round functions.
/// </summary>
public sealed partial class DEAL : 
    SymmetricEncryption
{
    #region Enumerations

    /// <summary>
    /// Supported key sizes for DEAL encryption algorithm.
    /// </summary>
    public enum DealKeySize
    {
        /// <summary>128-bit key.</summary>
        Key128 = 16,
        
        /// <summary>192-bit key.</summary>
        Key192 = 24,
        
        /// <summary>256-bit key.</summary>
        Key256 = 32
    }
    
    #endregion
    
    
    #region Fields

    /// <summary>
    /// The internal Feistel network used for Crypto.Core.DES encryption and decryption.
    /// </summary>
    private readonly FeistelNetwork _feistelNetwork;

    #endregion
    
    
    #region Properties

    /// <inherit/>
    public override byte[] Key
    {
        get => base.Key;
        set
        {
            if (base.Key == value)
            {
                return;
            }
            
            _feistelNetwork.Key = value;
            base.Key = value;
        }
    }
    
    #endregion
    
    
    #region Constructors
    
    /// <summary>
    /// Initializes a new instance of the <see cref="DEAL"/> class with a specified key, key schedule, key size,
    /// padding mode, cipher mode, and optional initialization vector and parameters.
    /// </summary>
    public DEAL(
        byte[] key,
        byte[] keyForSchedule,
        DealKeySize dealKeySize,
        SymmetricPaddingContext.SymmetricPaddingMode paddingMode,
        SymmetricModeContext.SymmetricMode mode,
        byte[]? initializationVector = null,
        params object[] parameters) : 
        base(16, (int)dealKeySize, key, paddingMode, mode, initializationVector, parameters)
    {
        var feistelRoundsCount = 
            dealKeySize == DealKeySize.Key256 ? 8 : 6;
        
        var desEncryption = 
            new DES(
                keyForSchedule,
                paddingMode,
                mode);
        
        IKeySchedule keySchedule = 
            new DEALKeySchedule(desEncryption, dealKeySize, keyForSchedule);
        
        IRoundFunction roundFunction = 
            new DESToDEALRoundFunctionAdapter(desEncryption);
        
        _feistelNetwork = 
            new FeistelNetwork(
                keySchedule, 
                roundFunction, 
                key, 
                feistelRoundsCount);
    }

    #endregion
    
    
    #region Methods
    
    /// <inheritdoc/>
    internal override void EncryptBlock(Memory<byte> data)
    {
        _feistelNetwork.Encrypt(data);
    }

    /// <inheritdoc/>
    internal override void DecryptBlock(Memory<byte> data)
    {
        _feistelNetwork.Decrypt(data);
    }
    
    #endregion
}