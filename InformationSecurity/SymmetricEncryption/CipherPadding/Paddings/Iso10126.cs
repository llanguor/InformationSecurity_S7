using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;

public class Iso10126 : ICipherPadding
{
    public void ApplyPadding(Span<byte> data, int blockSize)
    {
        throw new NotImplementedException();
    }

    public void RemovePadding(Span<byte> data, int blockSize)
    {
        throw new NotImplementedException();
    }
}