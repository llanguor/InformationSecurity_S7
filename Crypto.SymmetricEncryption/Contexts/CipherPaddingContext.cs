using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Paddings;

namespace Crypto.SymmetricEncryption.Contexts;

public class CipherPaddingContext(
    CipherPadding padding,
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    private readonly ICipherPadding _cipherPadding = padding switch
    {
        CipherPadding.ISO10126 => new ISO10126Padding(blockSize),
        CipherPadding.PKCS7 => new PKCS7Padding(blockSize),
        CipherPadding.Zeros => new ZerosPadding(blockSize),
        CipherPadding.ANSIX923 => new ANSIX923Padding(blockSize),
        _ => throw new ArgumentOutOfRangeException(nameof(padding), padding, null)
    };

    public override byte[] Apply(byte[] data)
    {
        return _cipherPadding.Apply(data);
    }

    public override byte[] Remove(byte[] data)
    {
        return _cipherPadding.Remove(data);
    }
}