using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base;

public abstract class CipherModeBase (
    Action<Memory<byte>> encryptionFunc,
    Action<Memory<byte>> decryptionFunc,
    int blockSize,
    Memory<byte>? initializationVector = null,
    params object[] parameters) 
    : ICipherMode
{
    #region Properties
    
    /// <summary>
    /// Optional initialization vector (IV) for certain cipher modes.
    /// </summary>
    protected Memory<byte>? InitializationVector { get; } = initializationVector;

    /// <summary>
    /// Additional optional parameters for the selected encryption mode.
    /// </summary>
    protected object[]? Parameters { get; } = parameters;

    /// <summary>
    /// Delegate representing the encryption function applied to each data block.
    /// This allows the encryption logic to be passed and executed dynamically.
    /// </summary>
    protected Action<Memory<byte>> EncryptionFunc { get; } = encryptionFunc;
    
    /// <summary>
    /// Delegate representing the decryption function applied to each data block.
    /// This allows the decryption logic to be passed and executed dynamically on a block of memory,
    /// typically reversing the operation performed by <see cref="EncryptionFunc"/>.
    /// </summary>
    protected Action<Memory<byte>> DecryptionFunc { get; } = decryptionFunc;
    
    /// <summary>
    /// Size of a single encryption block, in bytes.
    /// All input data is processed in chunks of this size.
    /// </summary>
    protected int BlockSize { get; } = blockSize;
    
    #endregion
    
    
    #region Methods
    
    public abstract void Encrypt(
        Memory<byte> data);
    
    public abstract void Decrypt(
        Memory<byte> data);
    
    public abstract Task EncryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default);
    
    public abstract Task DecryptAsync(
        Memory<byte> data,
        CancellationToken cancellationToken = default);
    
    #endregion
}