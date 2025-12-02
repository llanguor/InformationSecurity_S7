using System.Security.Cryptography;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.Paddings;

/// <summary>
/// Implements the PKCS#1 v1.5 padding scheme for RSA encryption and decryption.
/// </summary>
public sealed class PKCS1Padding(
    RSA.RSAKeySize keySize) :
    RSAPaddingBase(keySize)
{
    /// <inheritdoc/>
    public override int PlaintextBlockSize =>
        KeySizeInBytes - 11;

    /// <inheritdoc/>
    public override int CiphertextBlockSize => 
        KeySizeInBytes;
    
    /// <inheritdoc/>
    public override byte[] Apply(Span<byte> data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        
        var msgLen = data.Length;
        if (msgLen > PlaintextBlockSize)
        {
            throw new ArgumentException("Message too long.");
        }
        
        var paddingLen = KeySizeInBytes - msgLen - 3;
        if (paddingLen < 8)
        {
            throw new ArgumentException("Padding length must be at least 8.");
        }
        
        var block = 
            new byte[KeySizeInBytes];

        block[0] = 0x00;
        block[1] = 0x02;
        
        var padding =
            block.AsSpan(2, paddingLen);
        
        RandomNumberGenerator.Fill(padding);

        for (var i = 0; i < paddingLen; ++i)
        {
            var span = padding.Slice(i, 1);
            
            while (span[0] == 0x00)
            {
                RandomNumberGenerator.Fill(span);
            }
        }
        
        block[2 + paddingLen] = 0x00;
        data.CopyTo(
            block.AsSpan(
                3 + paddingLen));

        return block;
    }

    /// <inheritdoc/>
    public override byte[] Remove(Span<byte> data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        if (data.Length != CiphertextBlockSize)
        {
            throw new ArgumentException("The message must be the size of a key.");
        }

        if (data[0] != 0x00 ||
            data[1] != 0x02)
        {
            throw new ArgumentException("Incorrect input data.");
        }

        var msgStartIndex = 1;
        while (data[++msgStartIndex] != 0x00)
        {
            if (msgStartIndex == data.Length)
            {
                throw new ArgumentException("Incorrect input data.");
            }
        }
        ++msgStartIndex;

        if (msgStartIndex < 11)
        {
            throw new ArgumentException("Incorrect input data.");
        }

        return data.Slice(msgStartIndex).ToArray();
    }
}