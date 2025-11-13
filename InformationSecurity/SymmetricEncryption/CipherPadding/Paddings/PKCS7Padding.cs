using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;

public class PKCS7Padding(
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    public override byte[] Apply(byte[] data)
    {
        var padding = BlockSize - data.Length % BlockSize;
        var oldSize = data.Length;
        var newSize = data.Length + padding;
        
        var padded = new byte[newSize];
        data.CopyTo(padded, 0);

        for (var i = oldSize; i < newSize; ++i)
        {
            padded[i] = (byte)padding;
        }
        
        return padded;
    }

    public override byte[] Remove(byte[] data)
    {
        if (data.Length == 0 || data.Length % BlockSize != 0)
            throw new InvalidOperationException("Invalid data length for PKCS7 remove.");

        var padding = data[^1];
        if (padding <= 0 || padding > BlockSize)
            throw new InvalidOperationException("Invalid PKCS7 padding value.");
        
        for (var i = data.Length - padding; i < data.Length; i++)
        {
            if (data[i] != padding)
                throw new InvalidOperationException("Invalid PKCS7 padding bytes.");
        }
        
        var newSize = data.Length - padding;
        var unPadded = new byte[newSize];
        Array.Copy(data, unPadded, newSize);
        return unPadded;
    }
}