using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Contexts;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Provides a base implementation for symmetric block cipher encryption and decryption.
/// Supports configurable block size, key size, padding modes, and cipher modes.
/// Offers synchronous and asynchronous methods for processing byte arrays and files,
/// using an internal buffer for streaming operations.
/// </summary>
public abstract class SymmetricEncryption : 
    SymmetricEncryptionBase
{
    #region Properties

    /// <summary>
    /// Gets the internal buffer size used for streaming encryption and decryption.
    /// </summary>
    private int BufferSize { get; }  = 8 * 1024;
    
    #endregion
    
    
    #region Constructors

    /// <summary>
    /// Provides a base implementation for symmetric block cipher encryption and decryption.
    /// Supports configurable block size, key size, padding modes, and cipher modes.
    /// Offers synchronous and asynchronous methods for processing byte arrays and files,
    /// using an internal buffer for streaming operations.
    /// </summary>
    protected SymmetricEncryption(
        int blockSize,
        int keySize,
        byte[] key,
        SymmetricPaddingContext.SymmetricPaddingMode paddingMode,
        SymmetricModeContext.SymmetricMode mode,
        byte[]? initializationVector = null,
        params object[] parameters) :
        base(blockSize, keySize, key, paddingMode, mode, initializationVector, parameters)
    {
        if (blockSize <= 0)
            throw new ArgumentException("Block must be positive.", nameof(blockSize));
    }
    
    /// <summary>
    /// Initializes a new instance with a custom buffer size for streaming operations.
    /// </summary>
    protected SymmetricEncryption(
        int blockSize,
        int keySize,
        byte[] key, 
        SymmetricPaddingContext.SymmetricPaddingMode paddingMode, 
        SymmetricModeContext.SymmetricMode mode, 
        int bufferSize,
        byte[]? initializationVector = null, 
        params object[] parameters)
        : this(blockSize, keySize, key, paddingMode, mode, initializationVector, parameters)
    {
        if (bufferSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(bufferSize), "Buffer size must be positive.");
        
        BufferSize = bufferSize;
    }

    #endregion
    
    
    #region Sync Methods from SymmetricEncryptionBase Implementation
    
    /// <inheritdoc/>
    public override Memory<byte> Encrypt(Memory<byte> data)
    {
        if (data.Length == 0)
            return data;
        
        var result = PaddingContext.Apply(data.Span);
        ModeContext.Encrypt(result);
        return result;
    }
    
    /// <inheritdoc/>
    public override void Encrypt(
        byte[] data, 
        out byte[] result)
    {
        if (data.Length == 0)
            result = data;
        
        result = PaddingContext.Apply(data);
        ModeContext.Encrypt(result);
    }

    /// <inheritdoc/>
    public override void Encrypt(
        string inputFilePath,
        string outputFilePath)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
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
                var padded = PaddingContext.Apply(
                    buffer.AsSpan()[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToEncrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            ModeContext.Encrypt(dataToEncrypt);
            
            outputStream.Write(
                buffer, 
                0, 
                dataToEncrypt.Length);
        }
    }
    
    /// <inheritdoc/>
    public override Memory<byte> Decrypt(Memory<byte> data)
    {
        if (data.Length == 0)
            return data;
        
        ModeContext.Decrypt(data);
        return PaddingContext.Remove(data.Span);
    }

    /// <inheritdoc/>
    public override void Decrypt(
        byte[] data,
        out byte[] result)
    {
        if (data.Length == 0)
            result = data;
        
        ModeContext.Decrypt(data);
        result = PaddingContext.Remove(data);
    }

    /// <inheritdoc/>
    public override void Decrypt(
        string inputFilePath, 
        string outputFilePath)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
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
            
            ModeContext.Decrypt(dataToDecrypt);
            
            if (bytesRead != buffer.Length)
            {
                var padded = PaddingContext.Remove(
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
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length == 0)
            throw new ArgumentException("Data cannot be empty.", nameof(data));
        
        data = PaddingContext.Apply(data);
        await ModeContext.EncryptAsync(data, cancellationToken);
        return data;
    }

    /// <inheritdoc/>
    public override async Task EncryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var buffer = new byte[BufferSize];

        await using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        await using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        int bytesRead;
    
        while ((bytesRead = await inputStream.ReadAsync(buffer, cancellationToken)) > 0)
        {
            var dataToEncrypt =
                buffer.AsMemory()[..bytesRead];
            
            await ModeContext.EncryptAsync(dataToEncrypt, cancellationToken);
            
            if (bytesRead != buffer.Length)
            {
                var padded = PaddingContext.Apply(
                    buffer.AsSpan()[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToEncrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            await outputStream.WriteAsync(
                buffer.AsMemory(0, dataToEncrypt.Length),
                cancellationToken);
        }
    }
    
    /// <inheritdoc/>
    public override async Task<byte[]> DecryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        
        if (data.Length == 0)
            throw new ArgumentException("Data cannot be empty.", nameof(data));
        
        await ModeContext.DecryptAsync(data, cancellationToken);
        data = PaddingContext.Remove(data);
        return data;
    }

    /// <inheritdoc/>
    public override async Task DecryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var buffer = new byte[BufferSize];

        await using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        await using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        int bytesRead;
    
        while ((bytesRead = await inputStream.ReadAsync(buffer, cancellationToken)) > 0)
        {
            var dataToDecrypt =
                buffer.AsMemory()[..bytesRead];
            
            await ModeContext.DecryptAsync(dataToDecrypt, cancellationToken);
            
            if (bytesRead != buffer.Length)
            {
                var padded = PaddingContext.Remove(
                    buffer.AsSpan()[..bytesRead]);
                padded.CopyTo(buffer, 0);
                dataToDecrypt =
                    buffer.AsMemory()[..padded.Length];
            }
            
            await outputStream.WriteAsync(
                buffer.AsMemory(0, dataToDecrypt.Length),
                cancellationToken);
        }
    }

    #endregion
}