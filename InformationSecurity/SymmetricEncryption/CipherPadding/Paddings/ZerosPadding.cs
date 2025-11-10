using System.Data.Common;
using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;

public class ZerosPadding(
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    //Если длина данных не кратна размеру блока, последний блок надо дополнить до нужной длины.
    public override byte[] Apply(byte[] data)
    {
        if (data.Length % BlockSize == 0) 
            return data;
   
        var padded = new byte
        [
            BlockSize * (data.Length / BlockSize + 1)
        ];
        data.CopyTo(padded, 0);
        
        return padded;
    }

    public override byte[] Remove(byte[] data)
    {
        if (data.Length == 0 || data.Length % BlockSize != 0)
            throw new InvalidOperationException("Invalid data length for PKCS7 remove.");

        var newSize = data.Length;
        while (newSize > 0 && data[newSize - 1] == 0)
        {
            --newSize;
        }

        if (newSize == data.Length)
            return data;
        
        var unPadded = new byte[newSize];
        Array.Copy(data, unPadded, newSize);
        return unPadded;
    }
}