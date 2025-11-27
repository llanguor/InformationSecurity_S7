using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base;

public abstract class AsymmetricEncryptionBase<TKey> :
    IAsymmetricEncryption<TKey>
{
    #region Fields
    
    private readonly IKeyGenerator<TKey> _keyGenerator;
    
    private TKey _publicKey;
    
    private TKey _privateKey;
    
    #endregion
    
    
    #region Properties
    
    public TKey PublicKey => _publicKey;
    
    protected internal TKey PrivateKey => _privateKey;
    
    #endregion
    
    
    #region Constructors

    protected AsymmetricEncryptionBase(
        IKeyGenerator<TKey> keyGenerator)
    {
        _keyGenerator = keyGenerator;

        _keyGenerator.GenerateKeys(
            out _publicKey,
            out _privateKey);
    }
    
    #endregion
    
    
    #region Methods

    public void GenerateKeys()
    {
        _keyGenerator.GenerateKeys(
            out _publicKey, 
            out _privateKey);
    }
    
    /// <summary>
    /// Encrypts the specified data using the provided key./>.
    /// </summary>
    /// <param name="data">Input data to encrypt.</param>
    /// <returns>Encrypted data.</returns>
    public Memory<byte> Encrypt(
        Memory<byte> data)
    {
        return Encrypt(data, PrivateKey);
    }

    /// <summary>
    /// Decrypts the specified data using the provided RSA key./>.
    /// </summary>
    /// <param name="data">Input data to decrypt.</param>
    /// <returns>Decrypted data.</returns>
    public Memory<byte> Decrypt(
        Memory<byte> data)
    {
        return Decrypt(data, PrivateKey);
    }
    
    #endregion
    

    #region Abstract Methods

    public abstract Memory<byte> Encrypt(
        Memory<byte> data, TKey key);

    public abstract Memory<byte> Decrypt(
        Memory<byte> data, TKey key);

    #endregion
}