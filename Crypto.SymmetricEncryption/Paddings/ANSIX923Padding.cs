using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Paddings;

public class ANSIX923Padding(
    int blockSize) 
    : CipherPaddingBase(blockSize)
{
    public override byte[] Apply(Span<byte> data)
    {
        var padding = BlockSize - data.Length % BlockSize;
        var newSize = data.Length + padding;
        
        var padded = new byte[newSize];
        data.CopyTo(padded);
        padded[newSize - 1] = (byte)padding;

        return padded;
    }

    public override byte[] Remove(Span<byte> data)
    {
        if (data.Length == 0 || data.Length % BlockSize != 0)
            throw new InvalidOperationException("Invalid data length for ANSI X9.23 remove.");

        var padding = data[^1];
        if (padding <= 0 || padding > BlockSize)
            throw new InvalidOperationException("Invalid ANSI X9.23 padding value.");
        
        for (var i = data.Length - padding; i < data.Length - 1; i++)
        {
            if (data[i] != 0)
                throw new InvalidOperationException("Invalid ANSI X9.23 padding bytes.");
        }
        
        var newSize = data.Length - padding;
        var unPadded = new byte[newSize];
        data[..newSize].CopyTo(unPadded);
        
        return unPadded;
    }
}