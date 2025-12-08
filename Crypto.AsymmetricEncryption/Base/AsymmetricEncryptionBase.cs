using System.Collections.Immutable;
using System.Security.Cryptography;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base;

/// <summary>
/// Provides a base implementation for asymmetric encryption algorithms with key generation and padding support.
/// Handles encryption/decryption of data blocks, files, and asynchronous operations.
/// </summary>
/// <typeparam name="TKey">The type representing the asymmetric key.</typeparam>
public abstract class AsymmetricEncryptionBase<TKey> :
    IAsymmetricEncryption<TKey>
{
    #region Fields
    
    private readonly IKeyGenerator<TKey> _keyGenerator;
    
    private readonly IAsymmetricPadding _paddingContext;
    
    private TKey _publicKey;
    
    private TKey _privateKey;
    
    #endregion
    
    
    #region Properties
    
    /// <summary>
    /// Gets the public key of the algorithm.
    /// </summary>
    public virtual TKey PublicKey => 
        _publicKey;

    /// <summary>
    /// Gets the private key of the algorithm (accessible to derived classes and internal usage).
    /// </summary>
    public virtual TKey PrivateKey =>
        _privateKey;
    
    /// <summary>
    /// The size of the asymmetric key in bytes.
    /// </summary>
    protected int KeySize { get; }

    #endregion
    
    
    #region Constructors

    /// <summary>
    /// Initializes a new instance of the <see cref="AsymmetricEncryptionBase{TKey}"/> class.
    /// Generates the public and private keys using the provided key generator.
    /// </summary>
    /// <param name="keySize">The size of the key in bits.</param>
    /// <param name="keyGenerator">The key generator used to produce keys.</param>
    /// <param name="paddingContext">The padding context for block encryption/decryption.</param>
    protected AsymmetricEncryptionBase(
        int keySize,
        IKeyGenerator<TKey> keyGenerator,
        IAsymmetricPadding paddingContext)
    {
        if (keySize <= 0)
            throw new ArgumentOutOfRangeException(nameof(keySize), "Key size must be positive.");

        KeySize = keySize;
        _paddingContext = paddingContext ?? throw new ArgumentNullException(nameof(paddingContext));
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));

        _keyGenerator.GenerateKeys(
            out _publicKey,
            out _privateKey);
    }
    
    #endregion
    
    
    #region Abstract Methods for blocks

    /// <summary>
    /// Encrypts a single data block with the specified key.
    /// Must be implemented by derived classes.
    /// </summary>
    /// <param name="data">The block of data to encrypt.</param>
    /// <param name="key">The key used for encryption.</param>
    /// <returns>The encrypted data block.</returns>
    protected internal abstract Memory<byte> EncryptBlock(
        Memory<byte> data,
        TKey key);

    /// <summary>
    /// Decrypts a single data block with the specified key.
    /// Must be implemented by derived classes.
    /// </summary>
    /// <param name="data">The block of data to decrypt.</param>
    /// <param name="key">The key used for decryption.</param>
    /// <returns>The decrypted data block.</returns>
    protected internal abstract Memory<byte> DecryptBlock(
        Memory<byte> data,
        TKey key);
    
    #endregion
    
    
    #region Methods

    /// <summary>
    /// Generates a new pair of public and private keys using the configured key generator.
    /// </summary>
    public void GenerateKeys()
    {
        _keyGenerator.GenerateKeys(
            out _publicKey, 
            out _privateKey);
    }
    
    #endregion
    
    
    #region Private Methods
    
    private byte[] EncryptInternal(
        Memory<byte> data)
    {
        if (data.Length == 0)
            return data.ToArray();
        
        using var output = new MemoryStream();
        var bytesPerBlock = _paddingContext.PlaintextBlockSize;

        for (var i = 0; i < data.Length; i += bytesPerBlock)
        {
            var slice = data.Slice(
                i, 
                Math.Min(bytesPerBlock, data.Length - i));

            var padded =
                _paddingContext.Apply(slice.Span);
            
            var encrypted = 
                EncryptBlock(padded, PublicKey);
            
            output.Write(encrypted.Span);
        }
        
        return output.ToArray();
    }
    
    private async Task<byte[]> EncryptInternalAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default)
    {
        if (data.Length == 0)
            throw new ArgumentException("Data cannot be empty.", nameof(data));
        
        var bytesPerPlaintextBlock = _paddingContext.PlaintextBlockSize;
        var bytesPerCipherBlock = _paddingContext.CiphertextBlockSize;
        var blocksCount = (int) Math.Ceiling((double)data.Length / bytesPerPlaintextBlock);
        var output = new byte[blocksCount * bytesPerCipherBlock];
       
        await Parallel.ForAsync(
            0,
            blocksCount, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();

                var currentBlockStartIndex = i * bytesPerPlaintextBlock;
                var slice = data.Slice(
                    currentBlockStartIndex, 
                    Math.Min(
                        bytesPerPlaintextBlock,
                        data.Length - currentBlockStartIndex));

                var padded =
                    _paddingContext.Apply(slice.Span);

                var encrypted =
                    EncryptBlock(padded, PublicKey);
                
                encrypted.Span.CopyTo(
                    output.AsSpan(i * bytesPerCipherBlock));
                
                return ValueTask.CompletedTask;
            });
        
        return output;
    }
    
    private byte[] DecryptInternal(
        Memory<byte> data)
    {
        if (data.Length == 0)
            throw new ArgumentException("Data cannot be empty.", nameof(data));
        
        using var output = new MemoryStream();
        var bytesPerBlock = _paddingContext.CiphertextBlockSize;
        if (data.Length % bytesPerBlock != 0)
            throw new CryptographicException("Invalid block length for decryption");
        
        for (var i = 0; i < data.Length; i += bytesPerBlock)
        {
            var slice = data.Slice(
                i,
                bytesPerBlock);
            
            var decrypted = 
                DecryptBlock(slice, PrivateKey);
            
            var unPadded = 
                _paddingContext.Remove(decrypted.Span);
            
            output.Write(unPadded);
        }
        
        return output.ToArray();
    }

    private async Task<byte[]> DecryptInternalAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default)
    {
        if (data.Length == 0)
            throw new ArgumentException("Data cannot be empty.", nameof(data));
        
        var bytesPerPlaintextBlock = _paddingContext.PlaintextBlockSize;
        var bytesPerCipherBlock = _paddingContext.CiphertextBlockSize;
        if (data.Length % bytesPerCipherBlock != 0)
            throw new CryptographicException("Invalid block length for decryption");

        
        var blocksCount = data.Length / bytesPerCipherBlock - 1;
        
        var lastBlockSlice = data.Slice(
            blocksCount * bytesPerCipherBlock, 
            bytesPerCipherBlock);
                
        var lastBlockDecrypted =
            DecryptBlock(lastBlockSlice, PrivateKey);
                
        var lastBlockUnPadded = _paddingContext
            .Remove(lastBlockDecrypted.Span);
        
        var output = new byte[blocksCount * bytesPerPlaintextBlock + lastBlockUnPadded.Length];
        lastBlockUnPadded.CopyTo(output.AsSpan(blocksCount * bytesPerPlaintextBlock));
        
        
        await Parallel.ForAsync(
            0,
            blocksCount, 
            cancellationToken,
            (i, token) =>
            {
                token.ThrowIfCancellationRequested();

                var currentBlockStartIndex = i * bytesPerCipherBlock;
                var slice = data.Slice(
                    currentBlockStartIndex, 
                    bytesPerCipherBlock);
                
                var decrypted =
                    DecryptBlock(slice, PrivateKey);
                
                var unPadded = _paddingContext
                    .Remove(decrypted.Span);
                    
                unPadded.CopyTo(output.AsSpan(i * bytesPerPlaintextBlock));
                
                return ValueTask.CompletedTask;
            });
        
        return output;
    }
    
    #endregion
    
    
    #region Methods from IAsymmetricEncryption

    /// <inheritdoc/>
    public Memory<byte> Encrypt(
        Memory<byte> data)
    {
        return EncryptInternal(data);
    }

    /// <inheritdoc/>
    public Memory<byte> Decrypt(
        Memory<byte> data)
    {
        return DecryptInternal(data);
    }
    
    /// <inheritdoc/>
    public void Encrypt(
        byte[] data,
        out byte[] result)
    {
        result = EncryptInternal(data);
    }

    /// <inheritdoc/>
    public void Decrypt(
        byte[] data,
        out byte[] result)
    {
         result = DecryptInternal(data);
    }

    /// <inheritdoc/>
    public void Encrypt(
        string inputFilePath,
        string outputFilePath)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var bytesPerBlock = _paddingContext.PlaintextBlockSize;
        var buffer = new byte[bytesPerBlock];

        using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        int bytesRead;
        while ((bytesRead = inputStream.Read(buffer, 0, bytesPerBlock)) > 0)
        {
            byte[]? padded = null;

            if (bytesRead == bytesPerBlock)
            {
                padded =
                    _paddingContext.Apply(buffer);
            }
            else
            {
                padded = new byte[bytesRead];
                Array.Copy(buffer, padded, bytesRead);
                padded =
                    _paddingContext.Apply(padded);
            }
            
            var encrypted = 
                EncryptBlock(padded, PublicKey);

            var toWrite = encrypted.ToArray();
            outputStream.Write(
                toWrite, 
                0, 
                toWrite.Length);
        }
    }

    /// <inheritdoc/>
    public void Decrypt(
        string inputFilePath,
        string outputFilePath)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var bytesPerBlock = _paddingContext.CiphertextBlockSize;
        var buffer = new byte[bytesPerBlock];

        using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        while (inputStream.Read(buffer) > 0)
        {
            if (buffer.Length != bytesPerBlock)
                throw new CryptographicException("Invalid block length for decryption");
            
            var decrypted = 
                DecryptBlock(buffer, PrivateKey);
            
            var unPadded = 
                _paddingContext.Remove(decrypted.Span);
            
            var toWrite = unPadded.ToArray();
            outputStream.Write(
                toWrite, 
                0, 
                toWrite.Length);
        }
    }
      
    #endregion
    
    
    #region Async Methods from IAsymmetricEncryption

    /// <inheritdoc/>
    public async Task<byte[]> EncryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        return await EncryptInternalAsync(data, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<byte[]> DecryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        return await DecryptInternalAsync(data, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task EncryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var bytesPerBlock = _paddingContext.CiphertextBlockSize;
        var buffer = new byte[bytesPerBlock];

        await using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        await using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

        
        while (await inputStream.ReadAsync(buffer, cancellationToken) > 0)
        {
            if (buffer.Length != bytesPerBlock)
                throw new CryptographicException("Invalid block length for decryption");

            var decrypted =
                DecryptBlock(buffer, PrivateKey);

            var unPadded =
                _paddingContext.Remove(decrypted.Span);

            var toWrite = unPadded.ToArray();
            await outputStream.WriteAsync(toWrite, cancellationToken);
        }
    }

    /// <inheritdoc/>
    public async Task DecryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
            throw new ArgumentException("Input file path cannot be null or empty.", nameof(inputFilePath));
        
        var bytesPerBlock = _paddingContext.CiphertextBlockSize;
        var buffer = new byte[bytesPerBlock];

        await using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        await using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        while (await inputStream.ReadAsync(buffer, cancellationToken) > 0)
        {
            if (buffer.Length != bytesPerBlock)
                throw new CryptographicException("Invalid block length for decryption");
            
            var decrypted = 
                DecryptBlock(buffer, PrivateKey);
            
            var unPadded = 
                _paddingContext.Remove(decrypted.Span);
            
            var toWrite = unPadded.ToArray();
            await outputStream.WriteAsync(toWrite, cancellationToken);
        }
    }
    
    #endregion
}