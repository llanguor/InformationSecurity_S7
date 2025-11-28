using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA(
    PrimalityTest primalityTestType,
    RSAPaddingContext.RSAPaddingMode paddingMode,
    RSA.RSAKeySize keySize,
    double targetPrimaryProbability) :
        AsymmetricEncryptionBase<RSA.RSAKey>(
            (int)keySize/8,
            new RSAKeyGenerator(
                primalityTestType, 
                keySize,
                targetPrimaryProbability),
            new RSAPaddingContext(
                paddingMode,
                keySize))
{
    #region Fields
    
    private static readonly CryptoMathService CryptoMathService
        = new();
    
    #endregion
    
    
    #region Methods for blocks 
    
    protected internal override Memory<byte> EncryptBlock(Memory<byte> data, RSAKey key)
    {
        if(data.Length != KeySize)
            throw new ArgumentException("The data size must be equal to the key size", nameof(data));
        
        var dataBigInt = 
            new BigInteger(data.Span, true, true);

        var powered = CryptoMathService.ModPow(
            dataBigInt,
            key.Exponent,
            key.Modulus);
        
        data.Span.Clear();
        
        if (!powered.TryWriteBytes(
                data.Span.Slice(
                    KeySize - powered.GetByteCount(true)), 
                out _, 
                isBigEndian: true, 
                isUnsigned: true))
        {
            throw new CryptographicException("BigInteger too big for the key size");
        }

        return data;
    }
    
    protected internal override Memory<byte> DecryptBlock(Memory<byte> data, RSAKey key)
    {
        return EncryptBlock(data, key);
    }
}
    
    #endregion
