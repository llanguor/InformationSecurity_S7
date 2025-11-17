using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

//todo: add enum for key sizes

public sealed class DEAL : 
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
    
    public DEAL(
        byte[] key,
        byte[] keyForSchedule,
        DealKeySize dealKeySize,
        CipherPadding padding,
        CipherMode mode,
        byte[]? initializationVector = null,
        params object[] parameters) : 
        base(16, (int)dealKeySize, key, padding, mode, initializationVector, parameters)
    {
        var feistelRoundsCount = 
            dealKeySize == DealKeySize.Key256 ? 8 : 6;
        
        var desEncryption = 
            new DES(
                keyForSchedule,
                padding,
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
    
    internal override void EncryptBlock(Memory<byte> data)
    {
        _feistelNetwork.Encrypt(data);
    }

    internal override void DecryptBlock(Memory<byte> data)
    {
        _feistelNetwork.Decrypt(data);
    }
    
    #endregion
}