using Crypto.Core.Base;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Paddings;

/// <summary>
/// Implements the PKCS#7 padding scheme for block ciphers.
/// Pads data to a multiple of the block size by appending bytes
/// each containing the value of the padding length. Provides methods
/// to apply and remove padding securely.
/// </summary>
public class PKCS7Padding(
    int blockSize) 
    : SymmetricPaddingBase(blockSize)
{
    /// <inheritdoc/>   
    public override byte[] Apply(Span<byte> data)
    {
        var padding = BlockSize - data.Length % BlockSize;
        var oldSize = data.Length;
        var newSize = data.Length + padding;
        
        var padded = new byte[newSize];
        data.CopyTo(padded);

        for (var i = oldSize; i < newSize; ++i)
        {
            padded[i] = (byte)padding;
        }
        
        return padded;
    }

    /// <inheritdoc/>   
    public override byte[] Remove(Span<byte> data)
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
        data[..newSize].CopyTo(unPadded);
        
        return unPadded;
    }
}