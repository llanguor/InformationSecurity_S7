using InformationSecurity.SymmetricEncryption.Base;

namespace InformationSecurity.SymmetricEncryption.CipherMode.Base;

public abstract class CipherModeBase (
     byte[]? initializationVector = null,
     object[]? parameters = null)
    : ICipherMode
{
    /// <summary>
    /// Optional initialization vector (IV) for certain cipher modes.
    /// </summary>
    protected byte[]? InitializationVector { get; } = initializationVector;

    /// <summary>
    /// Additional optional parameters for the selected encryption mode.
    /// </summary>
    protected object[]? Parameters { get; } = parameters;
    
    
    public abstract void Encrypt(
        Span<byte> data, 
        IEncryption encryption,
        int blockSize);
    
    public abstract void Decrypt(
        Span<byte> data, 
        IEncryption encryption,
        int blockSize);
    
    public abstract Task EncryptAsync(
        Memory<byte> data, 
        IEncryption encryption,
        int blockSize);
    
    public abstract Task DecryptAsync(
        Memory<byte> data, 
        IEncryption encryption,
        int blockSize);
}