using InformationSecurity.SymmetricEncryption.CipherMode.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Context;
using InformationSecurity.SymmetricEncryption.CipherPadding.Base;
using InformationSecurity.SymmetricEncryption.CipherPadding.Context;

namespace InformationSecurity.SymmetricEncryption.Base;

/// <summary>
/// Represents the execution context for a symmetric encryption algorithm,
/// providing encryption and decryption operations with a specified key.
/// </summary>
public abstract class SymmetricEncryptionBase : IEncryption
{
    #region Properties
    
    /// <summary>
    /// The cipher mode used for block encryption and decryption operations.
    /// </summary>
    protected ICipherMode CipherMode { get; }

    /// <summary>
    /// The padding strategy applied to ensure blocks match the required block size.
    /// </summary>
    protected ICipherPadding CipherPadding { get; }
    
    /// <summary>
    /// Size of a single encryption block, in bytes.
    /// All input data is processed in chunks of this size.
    /// </summary>
    public int BlockSize { get; }
    
    /// <summary>
    /// The block cipher mode applied during encryption and decryption.
    /// </summary>
    public CipherMode.Enum.CipherMode Mode { get; }

    /// <summary>
    /// The padding scheme used to fill blocks to the required size.
    /// </summary>
    public CipherPadding.Enum.CipherPadding Padding { get; }
    
    /// <summary>
    /// The encryption key used for all operations.
    /// </summary>
    protected byte[] Key { get; }
    
    #endregion
    
    #region Constructors

    /// <summary>
    /// Represents the execution context for a symmetric encryption algorithm,
    /// providing encryption and decryption operations with a specified key.
    /// </summary>
    /// <param name="blockSize">Size of data block processed at a time in symmetric block cipher.</param>
    /// <param name="key">The encryption key used for all operations.</param>
    /// <param name="mode">The block cipher mode applied during encryption and decryption.</param>
    /// <param name="padding">The padding scheme used to fill blocks to the required size.</param>
    /// <param name="initializationVector">Optional initialization vector (IV) for certain cipher modes.</param>
    /// <param name="parameters">Additional optional parameters for the selected encryption mode.</param>
    protected SymmetricEncryptionBase(
        int blockSize,
        byte[] key,
        CipherPadding.Enum.CipherPadding padding,
        CipherMode.Enum.CipherMode mode,
        byte[]? initializationVector = null,
        params object[] parameters)
    {
        BlockSize = blockSize;
        Mode = mode;
        Padding = padding;
        Key = key;
        
        CipherPadding =
            new CipherPaddingContext(
                Padding,
                BlockSize);
        
        CipherMode = 
            new CipherModeContext(
                Mode,
                EncryptBlock,
                DecryptBlock,
                BlockSize,
                initializationVector, 
                parameters);
    }
    
    #endregion
    
    #region Abstract Methods
    
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
    
    /// <inheritdoc />
    public abstract void SetKey(byte[] key);
    
    /// <inheritdoc />
    public abstract byte[] Encrypt(byte[] data);
    
    /// <inheritdoc />
    public abstract byte[] Decrypt(byte[] data);
    
    /// <summary>
    /// Encrypts the provided byte array and outputs the result via an out parameter.
    /// The <paramref name="data"/> array is modified in-place during encryption.
    /// </summary>
    /// <param name="data">The data to encrypt. Modified in-place.</param>
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
    /// The <paramref name="data"/> array is modified in-place during decryption.
    /// </summary>
    /// <param name="data">The data to decrypt. Modified in-place.</param>
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
    /// The <paramref name="data"/> array is modified in-place during encryption.
    /// </summary>
    /// <param name="data">The data to encrypt. Modified in-place.</param>
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
    /// The <paramref name="data"/> array is modified in-place during decryption.
    /// </summary>
    /// <param name="data">The data to decrypt. Modified in-place.</param>
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
