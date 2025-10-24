using InformationSecurity.SymmetricEncryption.Base;

namespace InformationSecurity.SymmetricEncryption;

public class SymmetricEncryption(
    IEncryption encryptionAlgorithm,
    byte[] key, 
    SymmetricEncryptionBase.BlockCipherMode mode, 
    SymmetricEncryptionBase.BlockCipherPadding padding, 
    byte[]? initializationVector = null, 
    params object[] parameters) 
    : SymmetricEncryptionBase(key, mode, padding, initializationVector, parameters)
{
    #region Properties

    private readonly IEncryption _encryption = 
        encryptionAlgorithm;

    #endregion
    
    
    #region Override Methods
    
    public override void SetKey(byte[] key)
    {
        _encryption.SetKey(key);
    }

    #endregion
    
    
    #region  Override Methods Encrypt

    public override byte[] Encrypt(byte[] data)
    {
        throw new NotImplementedException();
    }

    public override void Encrypt(byte[] data, out byte[] result)
    {
        throw new NotImplementedException();
    }

    public override void Encrypt(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    public override async Task<byte[]> EncryptAsync(byte[] data)
    {
        throw new NotImplementedException();
    }

    public override async Task EncryptAsync(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    #endregion


    #region Override Methods Decrypt
    
    public override byte[] Decrypt(byte[] data)
    {
        throw new NotImplementedException();
    }

    public override void Decrypt(byte[] data, out byte[] result)
    {
        throw new NotImplementedException();
    }

    public override void Decrypt(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    public override async Task<byte[]> DecryptAsync(byte[] data)
    {
        throw new NotImplementedException();
    }

    public override async Task DecryptAsync(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    #endregion

}