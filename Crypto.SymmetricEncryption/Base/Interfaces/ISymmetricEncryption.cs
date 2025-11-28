using Crypto.Core;
using Crypto.Core.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base.Interfaces;

public interface ISymmetricEncryption :
    IEncryptionAlgorithm
{
    #region Properties
    
    /// <summary>
    /// Gets or sets the key used by the encryption algorithm.
    /// The key must be assigned before any encryption or decryption occurs.
    /// </summary>
    public byte[] Key { get; set; }
    
    /// <summary>
    /// Size of a single encryption block, in bytes.
    /// All input data is processed in chunks of this size.
    /// </summary>
    public int KeySize { get; }
    
    /// <summary>
    /// Size of a single encryption block, in bytes.
    /// All input data is processed in chunks of this size.
    /// </summary>
    public int BlockSize { get; }
    
    #endregion
}