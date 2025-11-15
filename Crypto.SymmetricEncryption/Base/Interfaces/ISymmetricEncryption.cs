using Crypto.Core;

namespace Crypto.SymmetricEncryption.Base.Interfaces;

public interface ISymmetricEncryption : 
    IEncryption
{
    #region Properties
    
    /// <summary>
    /// Size of a single encryption block, in bytes.
    /// All input data is processed in chunks of this size.
    /// </summary>
    public int BlockSize { get; }

    /// <summary>
    /// The block cipher mode applied during encryption and decryption.
    /// </summary>
    public CipherMode Mode { get; }
    
    /// <summary>
    /// The padding scheme used to fill blocks to the required size.
    /// </summary>
    public CipherPadding Padding { get; }
    
    /// <summary>
    /// Optional initialization vector (IV) for certain cipher modes.
    /// </summary>
    public byte[]? InitializationVector { get; }

    /// <summary>
    /// Additional optional parameters for the selected encryption mode.
    /// </summary>
    public object[] Parameters { get; }
    
    #endregion
    
    
    #region Methods
    
    /// <summary>
    /// Encrypts the provided byte array and outputs the result via an out parameter.
    /// The <paramref name="data"/> array is modified in-place during encryption.
    /// </summary>
    /// <param name="data">The data to encrypt. Modified in-place.</param>
    /// <param name="result">The resulting encrypted data.</param>
    public void Encrypt(byte[] data, out byte[] result);

    /// <summary>
    /// Encrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be encrypted.</param>
    /// <param name="outputFilePath">Path where the encrypted file will be saved.</param>
    public void Encrypt(string inputFilePath, string outputFilePath);

    /// <summary>
    /// Decrypts the provided byte array and outputs the result via an out parameter.
    /// The <paramref name="data"/> array is modified in-place during decryption.
    /// </summary>
    /// <param name="data">The data to decrypt. Modified in-place.</param>
    /// <param name="result">The resulting decrypted data.</param>
    public void Decrypt(byte[] data, out byte[] result);

    /// <summary>
    /// Decrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be decrypted.</param>
    /// <param name="outputFilePath">Path where the decrypted file will be saved.</param>
    public void Decrypt(string inputFilePath, string outputFilePath);
    
    /// <summary>
    /// Asynchronously encrypts the provided byte array using the current key, mode, and padding.
    /// The <paramref name="data"/> array is modified in-place during encryption.
    /// </summary>
    /// <param name="data">The data to encrypt. Modified in-place.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the encrypted byte array.</returns>
    public Task<byte[]> EncryptAsync(byte[] data);
    
    /// <summary>
    /// Asynchronously encrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be encrypted.</param>
    /// <param name="outputFilePath">Path where the encrypted file will be saved.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public Task EncryptAsync(string inputFilePath, string outputFilePath);
    
    /// <summary>
    /// Asynchronously decrypts the provided byte array using the current key, mode, and padding.
    /// The <paramref name="data"/> array is modified in-place during decryption.
    /// </summary>
    /// <param name="data">The data to decrypt. Modified in-place.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the decrypted byte array.</returns>
    public Task<byte[]> DecryptAsync(byte[] data);

    /// <summary>
    /// Asynchronously decrypts the contents of the input file and writes the result to the output file.
    /// </summary>
    /// <param name="inputFilePath">Path to the file to be decrypted.</param>
    /// <param name="outputFilePath">Path where the decrypted file will be saved.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public Task DecryptAsync(string inputFilePath, string outputFilePath);
    
    #endregion
}