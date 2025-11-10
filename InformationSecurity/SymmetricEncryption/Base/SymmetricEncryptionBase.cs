using InformationSecurity.SymmetricEncryption.CipherMode.Context;
using InformationSecurity.SymmetricEncryption.CipherPadding.Context;
namespace InformationSecurity.SymmetricEncryption.Base;


/// <summary>
/// Represents the execution context for a symmetric encryption algorithm,
/// providing encryption and decryption operations with a specified key.
/// </summary>
public abstract class SymmetricEncryptionBase : IEncryption
{
    #region Properties

    protected CipherModeContext CipherModeContext { get; }
    
    
    protected CipherPaddingContext CipherPaddingContext { get; }

    
    protected IEncryption Encryption { get; }
    
    
    protected int BlockSize { get; }
    
    /// <summary>
    /// The block cipher mode applied during encryption and decryption.
    /// </summary>
    protected CipherMode.Enum.CipherMode Mode { get; }

    /// <summary>
    /// The padding scheme used to fill blocks to the required size.
    /// </summary>
    protected CipherPadding.Enum.CipherPadding Padding { get; }
    
    /// <summary>
    /// The encryption key used for all operations.
    /// </summary>
    protected byte[] Key { get; }

    /// <summary>
    /// Optional initialization vector (IV) for certain cipher modes.
    /// </summary>
    protected byte[]? InitializationVector { get; }

    /// <summary>
    /// Additional optional parameters for the selected encryption mode.
    /// </summary>
    protected object[] Parameters { get; }

    #endregion
    
    
    #region Constructors
    
    /// <summary>
    /// Represents the execution context for a symmetric encryption algorithm,
    /// providing encryption and decryption operations with a specified key.
    /// </summary>
    /// /// <param name="encryptionAlgorithm">
    /// The specific symmetric encryption algorithm to be used for encrypting and decrypting blocks.
    /// This can be any implementation of the <see cref="IEncryption"/> interface.
    /// </param>
    /// <param name="key">The encryption key used for all operations.</param>
    /// <param name="mode">The block cipher mode applied during encryption and decryption.</param>
    /// <param name="padding">The padding scheme used to fill blocks to the required size.</param>
    /// <param name="initializationVector">Optional initialization vector (IV) for certain cipher modes.</param>
    /// <param name="parameters">Additional optional parameters for the selected encryption mode.</param>
    protected SymmetricEncryptionBase(
        IEncryption encryptionAlgorithm,
        int blockSize,
        byte[] key,
        CipherMode.Enum.CipherMode mode,
        CipherPadding.Enum.CipherPadding padding,
        byte[]? initializationVector = null,
        params object[] parameters)
    {
        Encryption = encryptionAlgorithm;
        BlockSize = blockSize;
        Mode = mode;
        Padding = padding;
        Key = key;
        InitializationVector = initializationVector;
        Parameters = parameters;

        CipherPaddingContext =
            new CipherPaddingContext(padding);
        
        CipherModeContext = 
            new CipherModeContext(
                mode,
                initializationVector, 
                parameters);
    }
    
    #endregion



    #region Methods

    /// <inheritdoc />
    public void SetKey(ReadOnlySpan<byte> key)
    {
        Encryption.SetKey(key);
    }

    #endregion
    
    
    #region Abstract Methods
    
    /// <inheritdoc />
    public abstract void Encrypt(Span<byte> data);
    
    /// <inheritdoc />
    public abstract void Decrypt(Span<byte> data);
    
    /// <summary>
    /// Encrypts the provided byte array and outputs the result via an out parameter.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="result">The resulting encrypted data.</param>
    public abstract void Encrypt(byte[] data, out byte[] result);

    /// <summary>
    /// Encrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be encrypted.</param>
    /// <param name="outputFilePath">Path where the encrypted file will be saved.</param>
    public abstract void Encrypt(string inputFilePath, string outputFilePath);

    /// <summary>
    /// Decrypts the provided byte array and outputs the result via an out parameter.
    /// </summary>
    /// <param name="data">The data to decrypt.</param>
    /// <param name="result">The resulting decrypted data.</param>
    public abstract void Decrypt(byte[] data, out byte[] result);

    /// <summary>
    /// Decrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be decrypted.</param>
    /// <param name="outputFilePath">Path where the decrypted file will be saved.</param>
    public abstract void Decrypt(string inputFilePath, string outputFilePath);
    
    #endregion
    
    
    #region Abstract Async Methods
    
    /// <summary>
    /// Asynchronously encrypts the provided byte array using the current key, mode, and padding.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the encrypted byte array.</returns>
    public abstract Task<byte[]> EncryptAsync(byte[] data);
    
    /// <summary>
    /// Asynchronously encrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be encrypted.</param>
    /// <param name="outputFilePath">Path where the encrypted file will be saved.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public abstract Task EncryptAsync(string inputFilePath, string outputFilePath);
    
    /// <summary>
    /// Asynchronously decrypts the provided byte array using the current key, mode, and padding.
    /// </summary>
    /// <param name="data">The data to decrypt.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the decrypted byte array.</returns>
    public abstract Task<byte[]> DecryptAsync(byte[] data);

    /// <summary>
    /// Asynchronously decrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be decrypted.</param>
    /// <param name="outputFilePath">Path where the decrypted file will be saved.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public abstract Task DecryptAsync(string inputFilePath, string outputFilePath);
    
    #endregion
}