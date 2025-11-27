using Crypto.Core.Base;
using Crypto.Core.Base.Interfaces;
using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Paddings;

namespace Crypto.SymmetricEncryption.Contexts;

public sealed class SymmetricPaddingContext :
    SymmetricPaddingBase
{
    #region Fields

    private ISymmetricPadding _paddingAlgorithm = null!;

    private SymmetricPaddingMode _paddingMode;

    #endregion
    
    
    #region Properties

    public SymmetricPaddingMode PaddingMode
    {
        get => _paddingMode;
        set
        {
            _paddingMode = value;
            _paddingAlgorithm = value switch
            {
                SymmetricPaddingMode.ISO10126 => new ISO10126Padding(BlockSize),
                SymmetricPaddingMode.PKCS7 => new PKCS7Padding(BlockSize),
                SymmetricPaddingMode.Zeros => new ZerosPadding(BlockSize),
                SymmetricPaddingMode.ANSIX923 => new ANSIX923Padding(BlockSize),
                _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
            };
        }
    }
    
    #endregion
    
    
    #region Enumerations
    
    /// <summary>
    /// Defines the supported padding schemes for symmetric encryption.
    /// Used to fill the last block to the required size if it is not complete.
    /// </summary>
    public enum SymmetricPaddingMode
    {
        /// <summary>
        /// Pads the block with zeros.
        /// </summary>
        Zeros,

        /// <summary>
        /// Pads the block according to ANSI X.923.
        /// </summary>
        ANSIX923,

        /// <summary>
        /// Pads the block according to PKCS#7.
        /// </summary>
        PKCS7,

        /// <summary>
        /// Pads the block according to ISO 10126 (random padding bytes).
        /// </summary>
        ISO10126
    }
    
    #endregion
    
    
    #region Constructors
    
    public SymmetricPaddingContext(
        SymmetricPaddingMode paddingMode,
        int blockSize) : 
        base(blockSize)
    {
        PaddingMode = paddingMode;
    }
    
    #endregion
    
    
    #region Methods

    public override byte[] Apply(Span<byte> data)
    {
        return _paddingAlgorithm.Apply(data);
    }

    public override byte[] Remove(Span<byte> data)
    {
        return _paddingAlgorithm.Remove(data);
    }
    
    #endregion
}