using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption;

public abstract class SymmetricEncryption : 
    SymmetricEncryptionBase
{
    #region Fields

    private readonly int _bufferSize = 8 * 1024;
    
    #endregion
    
    
    #region Constructors
    
    protected SymmetricEncryption(
        int blockSize,
        byte[] key, 
        CipherPaddings.CipherPaddings paddings, 
        CipherModes.CipherModes modes, 
        byte[]? initializationVector = null, 
        params object[] parameters)
        : base(
            blockSize, 
            key, 
            paddings, 
            modes, 
            initializationVector, 
            parameters)
    {
    }
    
    protected SymmetricEncryption(
        int blockSize,
        byte[] key, 
        CipherPaddings.CipherPaddings paddings, 
        CipherModes.CipherModes modes, 
        int bufferSize,
        byte[]? initializationVector = null, 
        params object[] parameters)
        : base(
            blockSize, 
            key, 
            paddings, 
            modes, 
            initializationVector, 
            parameters)
    {
        _bufferSize = bufferSize;
    }
    
    #endregion

    
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
                var padded = CipherPadding.Apply(
                    buffer[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToEncrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            CipherMode.Encrypt(dataToEncrypt);
            
            outputStream.Write(
                buffer, 
                0, 
                dataToEncrypt.Length);
        }
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
        result = CipherPadding.Remove(data);
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
            
            CipherMode.Decrypt(dataToDecrypt);
            
            if (bytesRead != buffer.Length)
            {
                var padded = CipherPadding.Remove(
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
        data = CipherPadding.Apply(data);
        await CipherMode.EncryptAsync(data);
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
            
            await CipherMode.EncryptAsync(dataToEncrypt);
            
            if (bytesRead != buffer.Length)
            {
                var padded = CipherPadding.Apply(
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
        await CipherMode.DecryptAsync(data);
        data = CipherPadding.Remove(data);
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
            
            await CipherMode.DecryptAsync(dataToDecrypt);
            
            if (bytesRead != buffer.Length)
            {
                var padded = CipherPadding.Remove(
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