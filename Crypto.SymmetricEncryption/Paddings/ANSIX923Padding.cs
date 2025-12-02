using Crypto.Core.Base;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Paddings;

/// <summary>
/// Implements the ANSI X9.23 padding scheme for block ciphers.
/// Pads data to a multiple of the block size with zeros followed by
/// a single byte indicating the padding length. Provides methods
/// to apply and remove padding safely.
/// </summary>
public class ANSIX923Padding(
    int blockSize) 
    : SymmetricPaddingBase(blockSize)
{
    /// <inheritdoc/>   
    public override byte[] Apply(Span<byte> data)
    {
        var padding = BlockSize - data.Length % BlockSize;
        var newSize = data.Length + padding;
        
        var padded = new byte[newSize];
        data.CopyTo(padded);
        padded[newSize - 1] = (byte)padding;

        return padded;
    }

    /// <inheritdoc/>   
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