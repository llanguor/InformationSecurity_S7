using InformationSecurity.SymmetricEncryption.Base;
namespace InformationSecurity.SymmetricEncryption;

public sealed class SymmetricEncryption(
    IEncryption encryptionAlgorithm,
    byte[] key, 
    SymmetricEncryptionBase.BlockCipherMode mode, 
    SymmetricEncryptionBase.BlockCipherPadding padding, 
    byte[]? initializationVector = null, 
    params object[] parameters) 
    : SymmetricEncryptionBase(key, mode, padding, initializationVector, parameters)
{
    #region Fields

    private readonly IEncryption _encryption = 
        encryptionAlgorithm;

    #endregion
    
    
    #region Override Methods
    
    /// <inheritdoc/>
    public override void SetKey(ReadOnlySpan<byte> key)
    {
        _encryption.SetKey(key);
    }

    #endregion
    
    
    #region  Override Methods Encrypt

    /// <inheritdoc/>
    public override void Encrypt(Span<byte> data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override void Encrypt(byte[] data, out byte[] result)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override void Encrypt(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    #endregion


    #region Override Methods Decrypt
    
    /// <inheritdoc/>
    public override void Decrypt(Span<byte> data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override void Decrypt(byte[] data, out byte[] result)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override void Decrypt(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    #endregion
    
    
    #region Async Methods
    
    /// <inheritdoc/>
    public override async Task<byte[]> EncryptAsync(byte[] data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    /// <inheritdoc/>
    public override async Task<byte[]> DecryptAsync(byte[] data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public override async Task DecryptAsync(string inputFilePath, string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    #endregion

}