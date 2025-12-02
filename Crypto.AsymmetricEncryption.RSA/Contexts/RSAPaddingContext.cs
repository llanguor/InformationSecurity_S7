using System.Security.Cryptography;
using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Paddings;

namespace Crypto.AsymmetricEncryption.Contexts;

/// <summary>
/// Context class for RSA padding that allows switching between different RSA padding modes.
/// </summary>
public sealed class RSAPaddingContext:
    RSAPaddingBase
{
    #region Fields
    
    private IRSAPadding _paddingAlgorithm = null!;
    
    private RSAPaddingMode _paddingMode;
    
    private readonly RSA.RSAKeySize _keySize;
    
    #endregion
    
    
    #region Properties
    
    /// <inheritdoc/>
    public override int PlaintextBlockSize => 
        _paddingAlgorithm.PlaintextBlockSize;
    
    /// <inheritdoc/>
    public override int CiphertextBlockSize =>
        _paddingAlgorithm.CiphertextBlockSize;

    /// <summary>
    /// Gets or sets the current RSA padding mode and updates the underlying padding algorithm accordingly.
    /// </summary>
    public RSAPaddingMode PaddingMode
    {
        get => _paddingMode;
        set
        {
            _paddingMode = value;
            _paddingAlgorithm = value switch
            {
                RSAPaddingMode.PKCS1 => new PKCS1Padding(_keySize),
                _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
            };
        }
    }

    #endregion


    #region Enumerations

    /// <summary>
    /// Specifies available RSA padding modes.
    /// </summary>
    public enum RSAPaddingMode
    {
        PKCS1
    }

    #endregion
    
    
    #region Constructors
    
    /// <summary>
    /// Initializes a new instance of the <see cref="RSAPaddingContext"/> class with the specified padding mode and key size.
    /// </summary>
    /// <param name="paddingMode">The RSA padding mode to use.</param>
    /// <param name="keySize">The size of the RSA key.</param>
    public RSAPaddingContext(
        RSAPaddingMode paddingMode,
        RSA.RSAKeySize keySize) : 
        base(keySize)
    {
        _keySize = keySize;
        PaddingMode = paddingMode;
    }
    
    #endregion
    
    
    #region Methods

    /// <inheritdoc/>
    public override byte[] Apply(Span<byte> data)
    {
        return _paddingAlgorithm.Apply(data);
    }

    /// <inheritdoc/>
    public override byte[] Remove(Span<byte> data)
    {
        return _paddingAlgorithm.Remove(data);
    }
    
    #endregion
}