namespace Crypto.Core;

/// <summary>
/// Represents a symmetric encryption algorithm.
/// Provides functionality for encrypting and decrypting blocks of data.
/// </summary>
public interface IEncryption
{
    /// <summary>
    /// Gets or sets the key used by the encryption algorithm.
    /// The key must be set before performing any encryption or decryption operations.
    /// </summary>
    public byte[] Key { get; set; }
    
    /// <summary>
    /// Sets the master key for the symmetric cipher.
    /// This method must be called before encrypting or decrypting data.
    /// </summary>
    /// <param name="key">The master key as a read-only span of bytes used to configure the cipher.</param>
    public void SetKey(byte[] key);

    /// <summary>
    /// Encrypts the specified block of data in-place.
    /// </summary>
    /// <param name="data">The input block to encrypt. It will be modified in-place.</param>
    public byte[] Encrypt(byte[] data);

    /// <summary>
    /// Decrypts the specified block of data in-place.
    /// </summary>
    /// <param name="data">The input block to decrypt. It will be modified in-place.</param>
    public byte[] Decrypt(byte[] data);
}