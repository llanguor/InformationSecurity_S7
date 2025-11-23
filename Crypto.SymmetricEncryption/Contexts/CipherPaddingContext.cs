using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Paddings;

namespace Crypto.SymmetricEncryption.Contexts;

public class CipherPaddingContext :
    CipherPaddingBase
{
    #region Fields

    private ICipherPadding _cipherPadding = null!;

    private CipherPadding _cipherPaddingType;

    #endregion
    
    
    #region Properties

    public CipherPadding CipherPaddingType
    {
        get => _cipherPaddingType;
        set
        {
            _cipherPaddingType = value;
            _cipherPadding = value switch
            {
                CipherPadding.ISO10126 => new ISO10126Padding(BlockSize),
                CipherPadding.PKCS7 => new PKCS7Padding(BlockSize),
                CipherPadding.Zeros => new ZerosPadding(BlockSize),
                CipherPadding.ANSIX923 => new ANSIX923Padding(BlockSize),
                _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
            };
        }
    }
    
    #endregion
    
    
    #region Constructors
    
    public CipherPaddingContext(
        CipherPadding padding,
        int blockSize) : 
        base(blockSize)
    {
        CipherPaddingType = padding;
    }
    
    #endregion
    
    
    #region Methods

    public override byte[] Apply(Span<byte> data)
    {
        return _cipherPadding.Apply(data);
    }

    public override byte[] Remove(Span<byte> data)
    {
        return _cipherPadding.Remove(data);
    }
    
    #endregion
}