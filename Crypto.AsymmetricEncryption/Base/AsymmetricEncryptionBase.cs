using System.Security.Cryptography;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base;

public abstract class AsymmetricEncryptionBase<TKey> :
    IAsymmetricEncryption<TKey>
{
    #region Fields
    
    private readonly IKeyGenerator<TKey> _keyGenerator;
    
    private readonly IAsymmetricPadding _paddingContext;
    
    private TKey _publicKey;
    
    private TKey _privateKey;
    
    #endregion
    
    
    #region Properties
    
    public virtual TKey PublicKey => 
        _publicKey;

    protected internal virtual TKey PrivateKey =>
        _privateKey;
    
    protected int KeySize { get; }

    #endregion
    
    
    #region Constructors

    protected AsymmetricEncryptionBase(
        int keySize,
        IKeyGenerator<TKey> keyGenerator,
        IAsymmetricPadding paddingContext)
    {
        KeySize = keySize;
        
        _paddingContext = paddingContext;
        
        _keyGenerator = keyGenerator;

        _keyGenerator.GenerateKeys(
            out _publicKey,
            out _privateKey);
    }
    
    #endregion
    
    
    #region Abstract Methods for blocks

    protected internal abstract Memory<byte> EncryptBlock(
        Memory<byte> data,
        TKey key);

    protected internal abstract Memory<byte> DecryptBlock(
        Memory<byte> data,
        TKey key);
    
    #endregion
    
    
    #region Methods

    public void GenerateKeys()
    {
        _keyGenerator.GenerateKeys(
            out _publicKey, 
            out _privateKey);
    }
    
    #endregion
    
    
    #region Private Methods
    
    private byte[] EncryptInternal(
        Memory<byte> data)
    {
        using var output = new MemoryStream();
        var bytesPerBlock = _paddingContext.PlaintextBlockSize;

        for (var i = 0; i < data.Length; i += bytesPerBlock)
        {
            var slice = data.Slice(
                i, 
                Math.Min(bytesPerBlock, data.Length - i));

            var padded =
                _paddingContext.Apply(slice.Span);
            
            var encrypted = 
                EncryptBlock(padded, PublicKey);
            
            output.Write(encrypted.Span);
        }
        
        return output.ToArray();
    }
    
    private byte[] DecryptInternal(
        Memory<byte> data)
    {
        using var output = new MemoryStream();
        var bytesPerBlock = _paddingContext.CiphertextBlockSize;
        
        for (var i = 0; i < data.Length; i += bytesPerBlock)
        {
            var slice = data.Slice(
                i,
                Math.Min(bytesPerBlock, data.Length - i));
            
            if (slice.Length != bytesPerBlock)
                throw new CryptographicException("Invalid block length for decryption");
            
            var decrypted = 
                DecryptBlock(slice, PrivateKey);
            
            var unPadded = 
                _paddingContext.Remove(decrypted.Span);
            
            output.Write(unPadded);
        }
        
        return output.ToArray();
    }

    
    #endregion
    
    
    #region Methods from IAsymmetricEncryption

    /// <inheritdoc/>
    public Memory<byte> Encrypt(
        Memory<byte> data)
    {
        return EncryptInternal(data);
    }

    /// <inheritdoc/>
    public Memory<byte> Decrypt(
        Memory<byte> data)
    {
        return DecryptInternal(data);
    }
    
    

    /// <inheritdoc/>
    public void Encrypt(
        byte[] data,
        out byte[] result)
    {
        result = EncryptInternal(data);
    }

    /// <inheritdoc/>
    public void Decrypt(
        byte[] data,
        out byte[] result)
    {
         result = DecryptInternal(data);
    }

    /// <inheritdoc/>
    public void Encrypt(
        string inputFilePath,
        string outputFilePath)
    {
        var bytesPerBlock = _paddingContext.PlaintextBlockSize;
        var buffer = new byte[bytesPerBlock];

        using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        while (inputStream.Read(buffer) > 0)
        {
            var padded =
                _paddingContext.Apply(buffer);
            
            var encrypted = 
                EncryptBlock(padded, PublicKey);

            var toWrite = encrypted.ToArray();
            outputStream.Write(
                toWrite, 
                0, 
                toWrite.Length);
        }
    }

    /// <inheritdoc/>
    public void Decrypt(
        string inputFilePath,
        string outputFilePath)
    {
        var bytesPerBlock = _paddingContext.CiphertextBlockSize;
        var buffer = new byte[bytesPerBlock];

        using var inputStream = 
            new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = 
            new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        while (inputStream.Read(buffer) > 0)
        {
            if (buffer.Length != bytesPerBlock)
                throw new CryptographicException("Invalid block length for decryption");
            
            var decrypted = 
                DecryptBlock(buffer, PrivateKey);
            
            var unPadded = 
                _paddingContext.Remove(decrypted.Span);
            
            var toWrite = unPadded.ToArray();
            outputStream.Write(
                toWrite, 
                0, 
                toWrite.Length);
        }
    }
      
    #endregion
    
    
    #region Async Methods from IAsymmetricEncryption

    /// <inheritdoc/>
    public Task<byte[]> EncryptAsync(
        byte[] data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public Task<byte[]> DecryptAsync(
        byte[] data)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public Task EncryptAsync(
        string inputFilePath,
        string outputFilePath)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public Task DecryptAsync(
        string inputFilePath,
        string outputFilePath)
    {
        throw new NotImplementedException();
    }
    
    #endregion
}