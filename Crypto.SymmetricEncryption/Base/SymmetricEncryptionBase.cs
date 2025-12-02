using System.Diagnostics.SymbolStore;
using Crypto.Core;
using Crypto.Core.Base.Interfaces;
using Crypto.SymmetricEncryption.Base.Interfaces;
using Crypto.SymmetricEncryption.Contexts;

namespace Crypto.SymmetricEncryption.Base;

/// <summary>
/// Represents the execution context for a symmetric encryption algorithm,
/// providing encryption and decryption operations with a specified key.
/// </summary>
public abstract class SymmetricEncryptionBase :
    ISymmetricEncryption
{
    #region Fields
    
    private byte[] _key;
    
    #endregion
    
    
    #region Properties

    /// <inheritdoc/>
    public virtual byte[] Key
    {
        get => _key;
        set
        {
            if(_key==null)
                throw new ArgumentNullException(nameof(value), "Key cannot be null."); 
            
            if (value.Length != KeySize)
                throw new ArgumentException($"Key length must be {KeySize} bytes.", nameof(value));

            _key = value;
            
        }
    }
    
    /// <inheritdoc/>
    public int BlockSize { get; }
    
    /// <inheritdoc/>
    public int KeySize { get; }
    
    /// <summary>
    /// The block cipher mode applied during encryption and decryption.
    /// </summary>
    public SymmetricModeContext.SymmetricMode Mode { get; }

    /// <summary>
    /// The padding scheme used to fill blocks to the required size.
    /// </summary>
    public SymmetricPaddingContext.SymmetricPaddingMode PaddingMode { get; }
    
    /// <summary>
    /// Optional initialization vector (IV) for certain cipher modes.
    /// </summary>
    public byte[]? InitializationVector { get; }
    
    /// <summary>
    /// Additional optional parameters for the selected encryption mode.
    /// </summary>
    public object[] Parameters { get; }

    /// <summary>
    /// The cipher mode used for block encryption and decryption operations.
    /// </summary>
    protected ISymmetricMode ModeContext { get; }

    /// <summary>
    /// The padding strategy applied to ensure blocks match the required block size.
    /// </summary>
    protected ISymmetricPadding PaddingContext { get; }
    
    #endregion
    
    
    #region Constructors
    
    /// <summary>
    /// Represents the execution context for a symmetric encryption algorithm,
    /// providing encryption and decryption operations with a specified key.
    /// </summary>
    /// <param name="blockSize">Size of data block processed at a time in symmetric block cipher.</param>
    /// <param name="keySize">Size of key using for encryption.</param>
    /// <param name="key">The secret key used by the symmetric encryption algorithm.</param>
    /// <param name="mode">The block cipher mode applied during encryption and decryption.</param>
    /// <param name="paddingMode">The padding scheme used to fill blocks to the required size.</param>
    /// <param name="initializationVector">Optional initialization vector (IV) for certain cipher modes.</param>
    /// <param name="parameters">Additional optional parameters for the selected encryption mode.</param>
    protected SymmetricEncryptionBase(
        int blockSize,
        int keySize,
        byte[] key,
        SymmetricPaddingContext.SymmetricPaddingMode paddingMode,
        SymmetricModeContext.SymmetricMode mode,
        byte[]? initializationVector = null,
        params object[] parameters)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be positive.");
        if (keySize <= 0)
            throw new ArgumentOutOfRangeException(nameof(keySize), "Key size must be positive.");
        if (key.Length != keySize)
            throw new ArgumentException($"Key length must be {keySize} bytes.", nameof(key));

        BlockSize = blockSize;
        KeySize = keySize;
        _key = key ?? throw new ArgumentNullException(nameof(key), "Key cannot be null.");
        Mode = mode;
        PaddingMode = paddingMode;
        InitializationVector = initializationVector;
        Parameters = parameters;
        
        PaddingContext =
            new SymmetricPaddingContext(
                PaddingMode,
                BlockSize);
        
        ModeContext = 
            new SymmetricModeContext(
                Mode,
                EncryptBlock,
                DecryptBlock,
                BlockSize,
                initializationVector, 
                parameters);
    }
    
    #endregion
    
    
    #region Abstract Methods for Block

    /// <summary>
    /// Encrypts a single block in-place.
    /// </summary>
    /// <param name="data">The data block to encrypt. Modified in-place.</param>
    internal abstract void EncryptBlock(Memory<byte> data);

    /// <summary>
    /// Decrypts a single block in-place.
    /// </summary>
    /// <param name="data">The data block to decrypt. Modified in-place.</param>
    internal abstract void DecryptBlock(Memory<byte> data);

    #endregion
    
    
    #region Abstract Methods from ISymmetricEncryption
    
    /// <inheritdoc/>
    public abstract Memory<byte> Encrypt(
        Memory<byte> data);

    /// <inheritdoc/>
    public abstract Memory<byte> Decrypt(
        Memory<byte> data);
    
    /// <inheritdoc/>
    public abstract void Encrypt(
        byte[] data,
        out byte[] result);

    /// <inheritdoc/>
    public abstract void Decrypt(
        byte[] data, 
        out byte[] result);
   
    /// <inheritdoc/>
    public abstract void Encrypt(
        string inputFilePath, 
        string outputFilePath);

    /// <inheritdoc/>
    public abstract void Decrypt(
        string inputFilePath, 
        string outputFilePath);
      
    #endregion
    
    
    #region Abstract Async Methods from ISymmetricEncryption
    
    /// <inheritdoc/>
    public abstract Task<byte[]> EncryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default);
    
    /// <inheritdoc/>
    public abstract Task<byte[]> DecryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default);
    
    /// <inheritdoc/>
    public abstract Task EncryptAsync(
        string inputFilePath, 
        string outputFilePath,
        CancellationToken cancellationToken = default);

    /// <inheritdoc/>
    public abstract Task DecryptAsync(
        string inputFilePath, 
        string outputFilePath,
        CancellationToken cancellationToken = default);
    
    #endregion
}
