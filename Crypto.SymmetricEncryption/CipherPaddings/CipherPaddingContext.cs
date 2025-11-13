using Crypto.SymmetricEncryption.CipherPaddings.Base;
using Crypto.SymmetricEncryption.CipherPaddings.Paddings;

namespace Crypto.SymmetricEncryption.CipherPaddings;

public class CipherPaddingContext(
    CipherPaddings paddings,
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    private readonly ICipherPadding _cipherPadding = paddings switch
    {
        CipherPaddings.ISO10126 => new ISO10126Padding(blockSize),
        CipherPaddings.PKCS7 => new PKCS7Padding(blockSize),
        CipherPaddings.Zeros => new ZerosPadding(blockSize),
        CipherPaddings.ANSIX923 => new ANSIX923Padding(blockSize),
        _ => throw new ArgumentOutOfRangeException(nameof(paddings), paddings, null)
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