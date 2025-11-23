using Crypto.Core;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface IAsymmetricEncryption<TKey> :
    IEncryption
{
    public Memory<byte> Encrypt(
        Memory<byte> data, 
        TKey key);
    
    public Memory<byte> Decrypt(
        Memory<byte> data, 
        TKey key);
}