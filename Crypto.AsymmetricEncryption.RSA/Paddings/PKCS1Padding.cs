using System.Security.Cryptography;
using Crypto.AsymmetricEncryption.Base;

namespace Crypto.AsymmetricEncryption.Paddings;

public sealed class PKCS1Padding(
    RSA.RSAKeySize keySize) :
    RSAPaddingBase(keySize)
{
    public override byte[] Apply(Span<byte> data)
    {
        var msgLen = data.Length;
        if (msgLen > KeySizeInBytes - 11)
        {
            throw new ArgumentException("Message too long.");
        }
        
        var paddingLen = KeySizeInBytes - msgLen - 3;
        if (paddingLen < 8)
        {
            throw new ArgumentException("PS length must be at least 8.");
        }
        
        var block = 
            new byte[KeySizeInBytes];

        block[0] = 0x00;
        block[1] = 0x02;
        block[2+paddingLen] = 0x02;
        data.CopyTo(
            block.AsSpan(
                3 + paddingLen, 
                msgLen));
        
        
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

        return block;
    }

    public override byte[] Remove(Span<byte> data)
    {
        if (data.Length != KeySizeInBytes)
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

        if (msgStartIndex < 10)
        {
            throw new ArgumentException("Incorrect input data.");
        }

        return data.Slice(msgStartIndex).ToArray();
    }
}