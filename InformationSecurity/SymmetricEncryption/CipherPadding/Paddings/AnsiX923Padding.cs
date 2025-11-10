using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;

public class AnsiX923Padding(
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    public override byte[] Apply(byte[] data)
    {
        throw new NotImplementedException();
    }

    public override byte[] Remove(byte[] data)
    {
        throw new NotImplementedException();
    }
}