using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
using InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Context;

public class CipherPaddingContext(
    Enum.CipherPadding padding,
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    private readonly ICipherPadding _cipherPadding = padding switch
    {
        Enum.CipherPadding.Iso10126 => new ISO10126Padding(blockSize),
        Enum.CipherPadding.Pkcs7 => new PKCS7Padding(blockSize),
        Enum.CipherPadding.Zeros => new ZerosPadding(blockSize),
        Enum.CipherPadding.AnsiX923 => new ANSIX923Padding(blockSize),
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