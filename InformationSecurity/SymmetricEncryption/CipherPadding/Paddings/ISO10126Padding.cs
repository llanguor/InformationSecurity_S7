using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
namespace InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;

public class ISO10126Padding(
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
        padded[newSize - 1] = (byte)padding;

        var random = new Random(Environment.TickCount);
        for (var i = oldSize; i < newSize - 1; i++)
        {
            padded[i] = (byte)random.Next(0, 256);
        }

        return padded;
    }

    public override byte[] Remove(byte[] data)
    {
        if (data.Length == 0 || data.Length % BlockSize != 0)
            throw new InvalidOperationException("Invalid data length for ISO10126 remove.");

        var padding = data[^1];
        if (padding <= 0 || padding > BlockSize)
            throw new InvalidOperationException("Invalid ISO10126 padding value.");
        
        var newSize = data.Length - padding;
        var unPadded = new byte[newSize];
        Array.Copy(data, unPadded, newSize);
        return unPadded;
    }
}