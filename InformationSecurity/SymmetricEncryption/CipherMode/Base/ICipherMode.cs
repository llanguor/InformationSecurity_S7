using InformationSecurity.SymmetricEncryption.Base;

namespace InformationSecurity.SymmetricEncryption.CipherMode.Base;

public interface ICipherMode
{
    public void Encrypt(
        Span<byte> data, 
        IEncryption encryption,
        int blockSize);
    
    public void Decrypt(
        Span<byte> data, 
        IEncryption encryption,
        int blockSize);
    
    public Task EncryptAsync(
        Memory<byte> data, 
        IEncryption encryption,
        int blockSize);
    
    public Task DecryptAsync(
        Memory<byte> data, 
        IEncryption encryption,
        int blockSize);
}