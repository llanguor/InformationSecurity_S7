using System.Numerics;
using System.Security.Cryptography;
using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA : 
    AsymmetricEncryptionBase<RSA.RSAKey>
{
    #region Fields
    
    private readonly IRSAPadding _paddingContext;
    
    private static readonly CryptoMathService CryptoMathService
        = new();
    
    #endregion
    
    
    #region Constructors
    
    public RSA(
        PrimalityTest primalityTestType,
        RSAPaddingContext.RSAPaddingMode paddingMode,
        RSAKeySize keySize,
        double targetPrimaryProbability):
        base(new RSAKeyGenerator(
                primalityTestType,
                keySize,
                targetPrimaryProbability))
    {
        _paddingContext = 
            new RSAPaddingContext(
            paddingMode, 
            keySize);
    }
    
    #endregion
    
    
    #region Methods
    
    /// <summary>
    /// Encrypts the specified data using the provided RSA key.
    /// </summary>
    /// <param name="data">Input data to encrypt.</param>
    /// <param name="key">RSA key used for encryption.</param>
    /// <returns>Encrypted data.</returns>
    /// <remarks>
    /// No key validation is performed internally.  
    /// The caller must ensure that the key is valid to maintain optimal performance.
    /// </remarks>
    public override Memory<byte> Encrypt(Memory<byte> data, RSAKey key)
    {
        using var output = new MemoryStream();
        var bytesPerBlock = key.Modulus.GetByteCount() - 11;

        for (var i = 0; i < data.Length; i += bytesPerBlock)
        {
            var slice = data.Slice(
                i, 
                Math.Min(bytesPerBlock, data.Length - i));

            var encrypted = EncryptBlock(slice, key);
            
            output.Write(encrypted.Span);
        }
        
        return output.ToArray();
    }

    /// <summary>
    /// Decrypts the specified data using the provided RSA key.
    /// </summary>
    /// <param name="data">Input data to decrypt.</param>
    /// <param name="key">RSA key used for decryption.</param>
    /// <returns>Decrypted data.</returns>
    /// <remarks>
    /// Key correctness is not verified inside this method.  
    /// The caller is responsible for supplying a valid key to avoid unnecessary overhead.
    /// </remarks>
    public override Memory<byte> Decrypt(Memory<byte> data, RSAKey key)
    {
        using var output = new MemoryStream();
        var bytesPerBlock = key.Modulus.GetByteCount();
        
        for (var i = 0; i < data.Length; i += bytesPerBlock)
        {
            var slice = data.Slice(
                i, 
                Math.Min(bytesPerBlock, data.Length - i));

            if (slice.Length != bytesPerBlock)
                throw new CryptographicException("Invalid block length for RSA decryption");
            
            var decrypted = DecryptBlock(slice, key);
            
            output.Write(decrypted.Span);
        }
        
        return output.ToArray();
    }
    
    #endregion
    
    
    #region Methods for blocks 
    
    internal Memory<byte> EncryptBlock(Memory<byte> data, RSAKey key)
    {
        var result = 
            _paddingContext.Apply(data.Span);
        
        var dataBigInt = 
            new BigInteger(result.AsSpan(), true, false);
        
        return CryptoMathService.ModPow(
                dataBigInt, 
                key.Exponent, 
                key.Modulus)
            .ToByteArray();
    }

    internal Memory<byte> DecryptBlock(Memory<byte> data, RSAKey key)
    {
        var dataBigInt = 
            new BigInteger(data.Span, true, false);

        var result = CryptoMathService.ModPow(
            dataBigInt,
            key.Exponent,
            key.Modulus)
            .ToByteArray();
        
        return _paddingContext.Remove(result);
    }
    
    #endregion
}