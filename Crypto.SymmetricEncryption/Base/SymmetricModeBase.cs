using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base;

/// <summary>
/// Base class for symmetric cipher modes, providing common properties
/// and delegates for encryption and decryption of memory blocks.
/// Supports optional initialization vector and additional parameters.
/// </summary>
public abstract class SymmetricModeBase : ISymmetricMode
{
    #region Constructors
    
    /// <summary>
    /// Base class for symmetric cipher modes, providing common properties
    /// and delegates for encryption and decryption of memory blocks.
    /// Supports optional initialization vector and additional parameters.
    /// </summary>
    protected SymmetricModeBase(Action<Memory<byte>> encryptionFunc,
        Action<Memory<byte>> decryptionFunc,
        int blockSize,
        Memory<byte>? initializationVector = null,
        params object[] parameters)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be positive.");
        
        if (initializationVector!=null &&
            initializationVector.Value.Length != blockSize)
            throw new ArgumentException("Initialization vector length must match block size.", nameof(initializationVector));
        
        InitializationVector = initializationVector;
        Parameters = parameters;
        EncryptionFunc = encryptionFunc ?? throw new ArgumentNullException(nameof(encryptionFunc));
        DecryptionFunc = decryptionFunc ?? throw new ArgumentNullException(nameof(decryptionFunc));
        BlockSize = blockSize;
    }
    
    #endregion

    #region Properties
    
    /// <summary>
    /// Optional initialization vector (IV) for certain cipher modes.
    /// </summary>
    protected Memory<byte>? InitializationVector { get; }

    /// <summary>
    /// Additional optional parameters for the selected encryption mode.
    /// </summary>
    protected object[]? Parameters { get; }

    /// <summary>
    /// Delegate representing the encryption function applied to each data block.
    /// This allows the encryption logic to be passed and executed dynamically.
    /// </summary>
    protected Action<Memory<byte>> EncryptionFunc { get; }
    
    /// <summary>
    /// Delegate representing the decryption function applied to each data block.
    /// This allows the decryption logic to be passed and executed dynamically on a block of memory,
    /// typically reversing the operation performed by <see cref="EncryptionFunc"/>.
    /// </summary>
    protected Action<Memory<byte>> DecryptionFunc { get; }
    
    /// <summary>
    /// Size of a single encryption block, in bytes.
    /// All input data is processed in chunks of this size.
    /// </summary>
    protected int BlockSize { get; }
    
    #endregion
    
    
    #region Methods

    protected void ThrowIfIncorrectInputData(Memory<byte> data)
    {
        if (data.IsEmpty)
            throw new ArgumentException("Data cannot be empty.", nameof(data));
        
        if (data.Length % BlockSize != 0)
            throw new ArgumentException("Data length must be a multiple of block size.", nameof(data));
    }

    protected void ThrowIfInitializationVectorIsNull()
    {
        if (InitializationVector == null)
            throw new InvalidOperationException("Initialization vector is not set.");
    }
    
    /// <inheritdoc/>
    public abstract void Encrypt(
        Memory<byte> data);
    
    /// <inheritdoc/>
    public abstract void Decrypt(
        Memory<byte> data);
    
    /// <inheritdoc/>
    public abstract Task EncryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default);
    
    /// <inheritdoc/>
    public abstract Task DecryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default);
    
    #endregion
}