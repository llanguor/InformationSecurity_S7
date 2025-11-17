using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Contexts;

namespace Crypto.SymmetricEncryption;

public abstract class SymmetricEncryption(
    int blockSize,
    int keySize,
    byte[] key,
    CipherPaddingContext.CipherPaddings paddings,
    CipherModeContext.CipherModes modes,
    byte[]? initializationVector = null,
    params object[] parameters) : 
    SymmetricEncryptionBase(blockSize, keySize, key, paddings, modes, initializationVector, parameters)
{
    
    #region Properties

    private int BufferSize { get; }  = 8 * 1024;
    
    
    #endregion
    
    
    #region Constructors

    protected SymmetricEncryption(
        int blockSize,
        int keySize,
        byte[] key, 
        CipherPaddingContext.CipherPaddings paddings, 
        CipherModeContext.CipherModes modes, 
        int bufferSize,
        byte[]? initializationVector = null, 
        params object[] parameters)
        : this(blockSize, keySize, key, paddings, modes, initializationVector, parameters)
    {
        BufferSize = bufferSize;
    }

    #endregion
    
    
    #region Sync Methods from SymmetricEncryptionBase Implementation
    
    /// <inheritdoc/>
    public override Memory<byte> Encrypt(Memory<byte> data)
    {
        var result = CipherPaddingContext.Apply(data.Span);
        CipherModeContext.Encrypt(result);
        return result;
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
        var buffer = new byte[BufferSize];

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
                    buffer.AsSpan()[..bytesRead]);
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
    public override Memory<byte> Decrypt(Memory<byte> data)
    {
        CipherModeContext.Decrypt(data);
        return CipherPaddingContext.Remove(data.Span);
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
        var buffer = new byte[BufferSize];

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
                    buffer.AsSpan()[..bytesRead]);
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
    
    
    #region Async Methods from SymmetricEncryptionBase Implementations

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
        var buffer = new byte[BufferSize];

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
                    buffer.AsSpan()[..bytesRead]);
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
        var buffer = new byte[BufferSize];

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
                    buffer.AsSpan()[..bytesRead]);
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