namespace InformationSecurity.SymmetricEncryption.Base;

/// <summary>
/// Represents the execution context for a symmetric encryption algorithm,
/// providing encryption and decryption operations with a specified key.
/// </summary>
/// <param name="key">The encryption key used for all operations.</param>
/// <param name="mode">The block cipher mode applied during encryption and decryption.</param>
/// <param name="padding">The padding scheme used to fill blocks to the required size.</param>
/// <param name="initializationVector">Optional initialization vector (IV) for certain cipher modes.</param>
/// <param name="parameters">Additional optional parameters for the selected encryption mode.</param>
public abstract class SymmetricEncryptionBase(
    byte[] key,
    SymmetricEncryptionBase.BlockCipherMode mode,
    SymmetricEncryptionBase.BlockCipherPadding padding,
    byte[]? initializationVector = null,
    params object[] parameters)
    : IEncryption
{
    #region Properties
    
    /// <summary>The block cipher mode applied during encryption and decryption.</summary>
    protected BlockCipherMode Mode { get; } = mode;

    /// <summary>The padding scheme used to fill blocks to the required size.</summary>
    protected BlockCipherPadding Padding { get; } = padding;
    
    /// <summary>The encryption key used for all operations.</summary>
    protected byte[] Key { get; } = key;

    /// <summary>Optional initialization vector (IV) for certain cipher modes.</summary>
    protected byte[]? InitializationVector { get; } = initializationVector;

    /// <summary>Additional optional parameters for the selected encryption mode.</summary>
    protected object[] Parameters { get; } = parameters;

    #endregion

    
    #region Enumerations
    
    /// <summary>
    /// Defines the supported block cipher modes for symmetric encryption.
    /// </summary>
    public enum BlockCipherMode
    {
        Ecb, 
        Cbc, 
        Pcbc, 
        Cfb, 
        Ofb, 
        Ctr, 
        RandomDelta
    }

    /// <summary>
    /// Defines the supported padding modes for symmetric encryption.
    /// </summary>
    public enum BlockCipherPadding
    {
        Zeros, 
        AnsiX923, 
        Pkcs7, 
        Iso10126
    }
    
    #endregion
    
    
    #region Overrides Methods
    
    /// <summary>
    /// Sets the encryption key to be used for all encryption and decryption operations.
    /// </summary>
    /// <param name="key">The symmetric encryption key.</param>
    public abstract void SetKey(byte[] key);

    /// <summary>
    /// Encrypts the provided byte array using the current key, mode, and padding.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <returns>The encrypted byte array.</returns>
    public abstract byte[] Encrypt(byte[] data);
    
    /// <summary>
    /// Decrypts the provided byte array using the current key, mode, and padding.
    /// </summary>
    /// <param name="data">The data to decrypt.</param>
    /// <returns>The decrypted byte array.</returns>
    public abstract byte[] Decrypt(byte[] data);
    
    #endregion
    
    
    #region Overload Methods
    
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
    
    
    #region Async Methods
    
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