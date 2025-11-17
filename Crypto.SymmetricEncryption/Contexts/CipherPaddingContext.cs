using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Paddings;

namespace Crypto.SymmetricEncryption.Contexts;

public class CipherPaddingContext(
    CipherPaddings paddings,
    int blockSize)
    : CipherPaddingBase(blockSize)
{
    #region Fields
    
    private readonly ICipherPadding _cipherPadding = paddings switch
    {
        CipherPaddings.ISO10126 => new ISO10126Padding(blockSize),
        CipherPaddings.PKCS7 => new PKCS7Padding(blockSize),
        CipherPaddings.Zeros => new ZerosPadding(blockSize),
        CipherPaddings.ANSIX923 => new ANSIX923Padding(blockSize),
        _ => throw new ArgumentOutOfRangeException(nameof(paddings), paddings, null)
    };

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