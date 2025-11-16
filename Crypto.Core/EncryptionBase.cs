namespace Crypto.Core;

public abstract class EncryptionBase(byte[] key):
    IEncryption
{
    #region Properties

    /// <inheritdoc />
    public virtual byte[] Key { get; set; } = key;

    #endregion
    
    
    #region Methods
    
    public byte[] Encrypt(byte[] data)
    {
        return Encrypt(data.AsMemory())
                .ToArray();
    }
    
    public byte[] Decrypt(byte[] data)
    {
        return Decrypt(data.AsMemory())
                .ToArray();
    }
    
    #endregion
    
    
    #region Abstract Methods
    
    /// <inheritdoc />
    public abstract Memory<byte> Encrypt(Memory<byte> data);

    /// <inheritdoc />
    public abstract Memory<byte> Decrypt(Memory<byte> data);
    
    #endregion
}