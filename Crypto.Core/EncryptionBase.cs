namespace Crypto.Core;

public abstract class EncryptionBase(byte[] key):
    IEncryption
{
    #region Properties

    /// <inheritdoc />
    public virtual byte[] Key { get; set; } = key;

    #endregion
    
    
    #region Methods

    /// <inheritdoc />
    public void SetKey(byte[] key) =>
        Key = key;

    #endregion
    
    
    #region Abstract Methods
    
    /// <inheritdoc />
    public abstract byte[] Encrypt(byte[] data);
    
    /// <inheritdoc />
    public abstract byte[] Decrypt(byte[] data);
    
    #endregion
}