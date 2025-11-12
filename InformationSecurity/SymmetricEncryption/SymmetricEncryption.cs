namespace InformationSecurity.SymmetricEncryption;
using Base;

public abstract class SymmetricEncryption(
    int blockSize,
    byte[] key, 
    CipherPadding.Enum.CipherPadding padding, 
    CipherMode.Enum.CipherMode mode, 
    byte[]? initializationVector = null, 
    params object[] parameters) 
    : SymmetricEncryptionBase(blockSize, key, padding, mode, initializationVector, parameters)
{
    #region Methods
    
    /// <inheritdoc/>
    public override byte[] Encrypt(byte[] data)
    {
        data = CipherPadding.Apply(data);
        CipherMode.Encrypt(data);
        return data;
    }
    
    /// <inheritdoc/>
    public override void Encrypt(
        byte[] data, 
        out byte[] result)
    {
        result = CipherPadding.Apply(data);
        CipherMode.Encrypt(result);
    }

    /// <inheritdoc/>
    public override void Encrypt(
        string inputFilePath,
        string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    /// <inheritdoc/>
    public override byte[] Decrypt(byte[] data)
    {
        CipherMode.Decrypt(data);
        data = CipherPadding.Remove(data);
        return data;
    }

    /// <inheritdoc/>
    public override void Decrypt(
        byte[] data,
        out byte[] result)
    {
        CipherMode.Decrypt(data);
        result = CipherPadding.Apply(data);
    }

    /// <inheritdoc/>
    public override void Decrypt(
        string inputFilePath, 
        string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    #endregion


    #region Async Methods

    /// <inheritdoc/>
    public override async Task<byte[]> EncryptAsync(
        byte[] data)
    {
        data = CipherPadding.Apply(data);
        await CipherMode.EncryptAsync(data);
        return data;
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(
        string inputFilePath,
        string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    /// <inheritdoc/>
    public override async Task<byte[]> DecryptAsync(
        byte[] data)
    {
        await CipherMode.DecryptAsync(data);
        data = CipherPadding.Remove(data);
        return data;
    }

    /// <inheritdoc/>
    public override async Task DecryptAsync(
        string inputFilePath,
        string outputFilePath)
    {
        throw new NotImplementedException();
    }

    #endregion
}