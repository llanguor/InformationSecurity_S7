using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
using InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Context;

public class CipherPaddingContext(Enum.CipherPadding padding) : ICipherPadding
{
    private readonly ICipherPadding _cipherPadding = padding switch
    {
        Enum.CipherPadding.Iso10126 => new Iso10126(),
        Enum.CipherPadding.Pkcs7 => new Pkcs7(),
        Enum.CipherPadding.Zeros => new Zeros(),
        Enum.CipherPadding.AnsiX923 => new AnsiX923(),
        _ => throw new ArgumentOutOfRangeException(nameof(padding), padding, null)
    };

    public void ApplyPadding(Span<byte> data, int blockSize)
    {
        _cipherPadding.ApplyPadding(data, blockSize);
    }

    public void RemovePadding(Span<byte> data, int blockSize)
    {
        _cipherPadding.RemovePadding(data, blockSize);
    }
}