using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption;

public abstract class SymmetricEncryption(
    int blockSize,
    byte[] key,
    CipherPadding padding,
    CipherMode mode,
    byte[]? initializationVector = null,
    params object[] parameters) : 
    SymmetricEncryptionBase(blockSize, key, padding, mode, initializationVector, parameters)
{
    #region Fields

    private readonly int _bufferSize = 8 * 1024;

    #endregion
    
    
    #region Constructors

    protected SymmetricEncryption(
        int blockSize,
        byte[] key, 
        CipherPadding padding, 
        CipherMode mode, 
        int bufferSize,
        byte[]? initializationVector = null, 
        params object[] parameters)
        : this(blockSize, key, padding, mode, initializationVector, parameters)
    {
        _bufferSize = bufferSize;
    }
    
    #endregion

    
    #region Methods
    
    /// <inheritdoc/>
    public override byte[] Encrypt(byte[] data)
    {
        data = CipherPaddingContext.Apply(data);
        CipherModeContext.Encrypt(data);
        return data;
    }
    
    /// <inheritdoc/>
    public override void Encrypt(
        byte[] data, 
        out byte[] result)
    {
        result = CipherPaddingContext.Apply(data);
        CipherModeContext.Encrypt(result);
    }

    /// <inheritdoc/>
    public override void Encrypt(
        string inputFilePath,
        string outputFilePath)
    {
        var buffer = new byte[_bufferSize];

        using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        int bytesRead;
    
        while ((bytesRead = inputStream.Read(buffer)) > 0)
        {
            Memory<byte> dataToEncrypt;
            if (bytesRead == buffer.Length)
            {
                dataToEncrypt =
                    buffer.AsMemory()[..bytesRead];
            }
            else
            {
                var padded = CipherPaddingContext.Apply(
                    buffer[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToEncrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            CipherModeContext.Encrypt(dataToEncrypt);
            
            outputStream.Write(
                buffer, 
                0, 
                dataToEncrypt.Length);
        }
    }
    
    /// <inheritdoc/>
    public override byte[] Decrypt(byte[] data)
    {
        CipherModeContext.Decrypt(data);
        data = CipherPaddingContext.Remove(data);
        return data;
    }

    /// <inheritdoc/>
    public override void Decrypt(
        byte[] data,
        out byte[] result)
    {
        CipherModeContext.Decrypt(data);
        result = CipherPaddingContext.Remove(data);
    }

    /// <inheritdoc/>
    public override void Decrypt(
        string inputFilePath, 
        string outputFilePath)
    {
        var buffer = new byte[_bufferSize];

        using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        int bytesRead;
    
        while ((bytesRead = inputStream.Read(buffer)) > 0)
        {
            var dataToDecrypt =
                buffer.AsMemory()[..bytesRead];
            
            CipherModeContext.Decrypt(dataToDecrypt);
            
            if (bytesRead != buffer.Length)
            {
                var padded = CipherPaddingContext.Remove(
                    buffer[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToDecrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            outputStream.Write(
                buffer, 
                0, 
                dataToDecrypt.Length);
        }
    }
    
    #endregion
    
    #region Async Methods

    /// <inheritdoc/>
    public override async Task<byte[]> EncryptAsync(
        byte[] data)
    {
        data = CipherPaddingContext.Apply(data);
        await CipherModeContext.EncryptAsync(data);
        return data;
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(
        string inputFilePath,
        string outputFilePath)
    {
        var buffer = new byte[_bufferSize];

        await using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        await using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        int bytesRead;
    
        while ((bytesRead = await inputStream.ReadAsync(buffer)) > 0)
        {
            var dataToEncrypt =
                buffer.AsMemory()[..bytesRead];
            
            await CipherModeContext.EncryptAsync(dataToEncrypt);
            
            if (bytesRead != buffer.Length)
            {
                var padded = CipherPaddingContext.Apply(
                    buffer[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToEncrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            await outputStream.WriteAsync(
                buffer.AsMemory(0, dataToEncrypt.Length));
        }
    }
    
    /// <inheritdoc/>
    public override async Task<byte[]> DecryptAsync(
        byte[] data)
    {
        await CipherModeContext.DecryptAsync(data);
        data = CipherPaddingContext.Remove(data);
        return data;
    }

    /// <inheritdoc/>
    public override async Task DecryptAsync(
        string inputFilePath,
        string outputFilePath)
    {
        var buffer = new byte[_bufferSize];

        await using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        await using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        int bytesRead;
    
        while ((bytesRead = await inputStream.ReadAsync(buffer)) > 0)
        {
            var dataToDecrypt =
                buffer.AsMemory()[..bytesRead];
            
            await CipherModeContext.DecryptAsync(dataToDecrypt);
            
            if (bytesRead != buffer.Length)
            {
                var padded = CipherPaddingContext.Remove(
                    buffer[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToDecrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            await outputStream.WriteAsync(
                buffer.AsMemory(0, dataToDecrypt.Length));
        }
    }

    #endregion
}