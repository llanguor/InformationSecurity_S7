using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Paddings;

public class ZerosPadding(
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    //Если длина данных не кратна размеру блока, последний блок надо дополнить до нужной длины.
    public override byte[] Apply(byte[] data)
    {
        var rem = data.Length % BlockSize;
        if (rem == 0) 
            return data;
        
        var padding = BlockSize - rem;
        var newSize = data.Length + padding;
   
        var padded = new byte[newSize];
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