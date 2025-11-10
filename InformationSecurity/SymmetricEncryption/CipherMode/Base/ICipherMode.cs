using InformationSecurity.SymmetricEncryption.Base;

namespace InformationSecurity.SymmetricEncryption.CipherMode.Base;

public interface ICipherMode
{
    public void Encrypt(Memory<byte> data);
    
    public void Decrypt(Memory<byte> data);
    
    public Task EncryptAsync(Memory<byte> data);
    
    public Task DecryptAsync(Memory<byte> data);
}