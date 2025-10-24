namespace InformationSecurity.SymmetricEncryption.Base;

/// <summary>
/// Represents a symmetric encryption algorithm.
/// Provides functionality for encrypting and decrypting blocks of data.
/// </summary>
public interface IEncryption
{
    /// <summary>
    /// Sets the master key for the symmetric cipher.
    /// This method must be called before encrypting or decrypting data.
    /// </summary>
    /// <param name="key">The master key as a byte array used to configure the cipher.</param>
    void SetKey(byte[] key);
    
    /// <summary>
    /// Encrypts the specified block of data.
    /// </summary>
    /// <param name="data">The input block to encrypt as a byte array.</param>
    /// <returns>The encrypted output block as a byte array.</returns>
    byte[] Encrypt(byte[] data);

    /// <summary>
    /// Decrypts the specified block of data.
    /// </summary>
    /// <param name="data">The input block to decrypt as a byte array.</param>
    /// <returns>The decrypted output block as a byte array.</returns>
    byte[] Decrypt(byte[] data);
}