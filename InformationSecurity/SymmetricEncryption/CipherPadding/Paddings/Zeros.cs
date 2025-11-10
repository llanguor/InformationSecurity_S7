using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;

public class Zeros : ICipherPadding
{
    //Если длина данных не кратна размеру блока, последний блок надо дополнить до нужной длины.
    public void ApplyPadding(Span<byte> data, int blockSize)
    {
        throw new NotImplementedException();
    }

    public void RemovePadding(Span<byte> data, int blockSize)
    {
        throw new NotImplementedException();
    }
}