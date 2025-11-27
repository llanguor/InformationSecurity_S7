using System.Security.Cryptography;
using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Paddings;

namespace Crypto.AsymmetricEncryption.Contexts;

public sealed class RSAPaddingContext:
    RSAPaddingBase
{
    #region Fields
    
    private IRSAPadding _paddingAlgorithm = null!;
    
    private RSAPaddingMode _paddingMode;
    
    private readonly RSA.RSAKeySize _keySize;
    
    #endregion
    
    
    #region Properties

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

    public enum RSAPaddingMode
    {
        PKCS1
    }

    #endregion
    
    
    #region Constructors
    
    public RSAPaddingContext(
        RSAPaddingMode paddingMode,
        RSA.RSAKeySize keySize) : 
        base(keySize)
    {
        PaddingMode = paddingMode;
        _keySize = keySize;
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