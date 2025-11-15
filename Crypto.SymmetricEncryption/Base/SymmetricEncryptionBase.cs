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
    
    /// <summary>
    /// The cipher mode used for block encryption and decryption operations.
    /// </summary>
    protected ICipherMode CipherModeContext { get; }

    /// <summary>
    /// The padding strategy applied to ensure blocks match the required block size.
    /// </summary>
    protected ICipherPadding CipherPaddingContext { get; }
    
    #endregion
    
    
    #region Properties Implementation from ISymmetricEncryption
    
    /// <inheritdoc />
    public virtual byte[] Key
    {
        get => _key;
        set => _key = value;
    }

    /// <inheritdoc />
    public int BlockSize { get; }

    /// <inheritdoc />
    public CipherMode Mode { get; set; }

    /// <inheritdoc />
    public CipherPadding Padding { get; }
    
    /// <inheritdoc />
    public byte[]? InitializationVector { get; }
    
    /// <inheritdoc />
    public object[] Parameters { get; }

    #endregion
    
    
    #region Constructors

    /// <summary>
    /// Represents the execution context for a symmetric encryption algorithm,
    /// providing encryption and decryption operations with a specified key.
    /// </summary>
    /// <param name="blockSize">Size of data block processed at a time in symmetric block cipher.</param>
    /// <param name="key">The secret key used by the symmetric encryption algorithm.</param>
    /// <param name="mode">The block cipher mode applied during encryption and decryption.</param>
    /// <param name="padding">The padding scheme used to fill blocks to the required size.</param>
    /// <param name="initializationVector">Optional initialization vector (IV) for certain cipher modes.</param>
    /// <param name="parameters">Additional optional parameters for the selected encryption mode.</param>
    protected SymmetricEncryptionBase(
        int blockSize,
        byte[] key,
        CipherPadding padding,
        CipherMode mode,
        byte[]? initializationVector = null,
        params object[] parameters)
    {
        BlockSize = blockSize;
        _key = key;
        Mode = mode;
        Padding = padding;
        InitializationVector = initializationVector;
        Parameters = parameters;

        CipherPaddingContext =
            new CipherPaddingContext(
                Padding,
                BlockSize);
        
        CipherModeContext = 
            new CipherModeContext(
                Mode,
                EncryptBlock,
                DecryptBlock,
                BlockSize,
                initializationVector, 
                parameters);
    }
    
    #endregion
    
    
    #region Methods
    
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
    
    
    #region Methods Implementation from ISymmetricEncryption 

    /// <inheritdoc />
    public void SetKey(byte[] key) => Key = key;
    
    /// <inheritdoc />
    public abstract byte[] Encrypt(byte[] data);
    
    /// <inheritdoc />
    public abstract byte[] Decrypt(byte[] data);

    /// <inheritdoc />
    public abstract void Encrypt(byte[] data, out byte[] result);

    /// <inheritdoc />
    public abstract void Encrypt(string inputFilePath, string outputFilePath);

    /// <inheritdoc />
    public abstract void Decrypt(byte[] data, out byte[] result);

    /// <inheritdoc />
    public abstract void Decrypt(string inputFilePath, string outputFilePath);

    /// <inheritdoc />
    public abstract Task<byte[]> EncryptAsync(byte[] data);
    
    /// <inheritdoc />
    public abstract Task EncryptAsync(string inputFilePath, string outputFilePath);
    
    /// <inheritdoc />
    public abstract Task<byte[]> DecryptAsync(byte[] data);

    /// <inheritdoc />
    public abstract Task DecryptAsync(string inputFilePath, string outputFilePath);
    
    #endregion
}
