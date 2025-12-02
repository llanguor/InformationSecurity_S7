using Crypto.Core.Base;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption.Paddings;

/// <summary>
/// Implements zero-byte padding for block ciphers.
/// Pads data to a multiple of the block size by appending zero bytes.
/// Provides methods to apply and remove padding, handling trailing zeros correctly.
/// </summary>
public class ZerosPadding(
    int blockSize) 
    : SymmetricPaddingBase(blockSize)
{
    /// <inheritdoc/>   
    public override byte[] Apply(Span<byte> data)
    {
        var rem = data.Length % BlockSize;
        if (rem == 0) 
            return data.ToArray();
        
        var padding = BlockSize - rem;
        var newSize = data.Length + padding;
   
        var padded = new byte[newSize];
        data.CopyTo(padded);
        
        return padded;
    }

    /// <inheritdoc/>   
    public override byte[] Remove(Span<byte> data)
    {
        if (data.Length == 0 || data.Length % BlockSize != 0)
            throw new InvalidOperationException("Invalid data length for PKCS7 remove.");

        var newSize = data.Length;
        while (newSize > 0 && data[newSize - 1] == 0)
        {
            --newSize;
        }

        if (newSize == data.Length)
            return data.ToArray();
        
        var unPadded = new byte[newSize];
        data[..newSize].CopyTo(unPadded);
        
        return unPadded;
    }
}