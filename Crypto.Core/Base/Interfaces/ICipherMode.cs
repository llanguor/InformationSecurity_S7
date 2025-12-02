namespace Crypto.Core.Base.Interfaces;

/// <summary>
/// Defines a symmetric block cipher mode of operation.
/// Provides synchronous and asynchronous methods for encrypting and decrypting data blocks.
/// </summary>
public interface ICipherMode
{
    /// <summary>
    /// Encrypts the specified data block in-place.
    /// </summary>
    /// <param name="data">Memory buffer containing the data to encrypt.</param>
    public void Encrypt(Memory<byte> data);
    
    /// <summary>
    /// Decrypts the specified data block in-place.
    /// </summary>
    /// <param name="data">Memory buffer containing the data to decrypt.</param>
    public void Decrypt(Memory<byte> data);
    
    /// <summary>
    /// Asynchronously encrypts the specified data block in-place.
    /// </summary>
    /// <param name="data">Memory buffer containing the data to encrypt.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    public Task EncryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Asynchronously decrypts the specified data block in-place.
    /// </summary>
    /// <param name="data">Memory buffer containing the data to decrypt.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    public Task DecryptAsync(
        Memory<byte> data, 
        CancellationToken cancellationToken = default);
}