namespace Crypto.Core;

/// <summary>
/// Represents a symmetric encryption algorithm.
/// Provides functionality for encrypting and decrypting blocks of data.
/// </summary>
public interface IEncryption
{
    /// <summary>
    /// Gets or sets the key used by the encryption algorithm.
    /// The key must be assigned before any encryption or decryption occurs.
    /// </summary>
    public byte[] Key { get; set; }

    /// <summary>
    /// Encrypts the specified block of data in-place.
    /// </summary>
    /// <param name="data">The input block to encrypt. It will be modified in-place.</param>
    /// <returns>A new byte array containing the encrypted data.</returns>
    public byte[] Encrypt(byte[] data);

    /// <summary>
    /// Decrypts the specified block of data in-place.
    /// </summary>
    /// <param name="data">The input block to decrypt. It will be modified in-place.</param>
    /// <returns>A new byte array containing the decrypted data.</returns>
    public byte[] Decrypt(byte[] data);
    
}