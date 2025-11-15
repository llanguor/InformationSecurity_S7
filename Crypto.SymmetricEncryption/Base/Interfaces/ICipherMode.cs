namespace Crypto.SymmetricEncryption.Base.Interfaces;

public interface ICipherMode
{
    public void Encrypt(Memory<byte> data);
    
    public void Decrypt(Memory<byte> data);
    
    public Task EncryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default);
    
    public Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default);
}