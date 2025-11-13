using Crypto.SymmetricEncryption.CipherModes;
using Crypto.SymmetricEncryption.CipherModes.Base;
using Crypto.SymmetricEncryption.CipherPaddings;
using Crypto.SymmetricEncryption.CipherPaddings.Base;

namespace Crypto.SymmetricEncryption.Base;

/// <summary>
/// Represents the execution context for a symmetric encryption algorithm,
/// providing encryption and decryption operations with a specified key.
/// </summary>
public abstract class SymmetricEncryptionBase : ISymmetricEncryption
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
    public CipherModes.CipherModes Modes { get; }

    /// <summary>
    /// The padding scheme used to fill blocks to the required size.
    /// </summary>
    public CipherPaddings.CipherPaddings Paddings { get; }
    
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
    /// <param name="modes">The block cipher mode applied during encryption and decryption.</param>
    /// <param name="paddings">The padding scheme used to fill blocks to the required size.</param>
    /// <param name="initializationVector">Optional initialization vector (IV) for certain cipher modes.</param>
    /// <param name="parameters">Additional optional parameters for the selected encryption mode.</param>
    protected SymmetricEncryptionBase(
        int blockSize,
        byte[] key,
        CipherPaddings.CipherPaddings paddings,
        CipherModes.CipherModes modes,
        byte[]? initializationVector = null,
        params object[] parameters)
    {
        BlockSize = blockSize;
        Modes = modes;
        Paddings = paddings;
        Key = key;
        
        CipherPadding =
            new CipherPaddingContext(
                Paddings,
                BlockSize);
        
        CipherMode = 
            new CipherModeContext(
                Modes,
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
    
    #endregion
    
    
    #region Abstract Methods from interface
    
    /// <inheritdoc />
    public abstract void SetKey(byte[] key);
    
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
