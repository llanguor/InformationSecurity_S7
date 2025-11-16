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
    /// Encrypts the specified block of data. 
    /// The input <paramref name="data"/> may be modified in-place if padding or internal buffers require it.
    /// </summary>
    /// <param name="data">The input block to encrypt.</param>
    /// <returns>
    /// A new byte array containing the encrypted data. 
    /// The returned array may differ from the original if padding was applied.
    /// </returns>
    public byte[] Encrypt(byte[] data);
    
    /// <summary>
    /// Encrypts the specified block of data. 
    /// The input <paramref name="data"/> may be modified in-place if padding or internal buffers require it.
    /// </summary>
    /// <param name="data">The input block to encrypt.</param>
    /// <returns>
    /// A <see cref="Memory{Byte}"/> containing the encrypted data. 
    /// This may wrap a new array if padding was added or internal buffers were used.
    /// </returns>
    public Memory<byte> Encrypt(Memory<byte> data);

    /// <summary>
    /// Decrypts the specified block of data. 
    /// The input <paramref name="data"/> may be modified in-place if padding removal or internal buffers require it.
    /// </summary>
    /// <param name="data">The input block to decrypt.</param>
    /// <returns>
    /// A new byte array containing the decrypted data. 
    /// The returned array may differ from the original if padding was removed or internal buffers were used.
    /// </returns>
    public byte[] Decrypt(byte[] data);
    
    /// <summary>
    /// Decrypts the specified block of data. 
    /// The input <paramref name="data"/> may be modified in-place if padding removal or internal buffers require it.
    /// </summary>
    /// <param name="data">The input block to decrypt.</param>
    /// <returns>
    /// A <see cref="Memory{Byte}"/> containing the decrypted data. 
    /// This may wrap a new array if padding was removed or internal buffers were used.
    /// </returns>
    public Memory<byte> Decrypt(Memory<byte> data);
}