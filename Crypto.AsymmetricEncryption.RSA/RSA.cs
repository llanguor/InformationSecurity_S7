using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA : 
    IAsymmetricEncryption<RSA.RSAKey>
{
    #region Fields
    
    private readonly RSAKeyGenerator _keyGenerator;
    
    private readonly RSAKey _publicKey;
    
    private readonly RSAKey _privateKey;
    
    private static readonly CryptoMathService _cryptoMathService
        = new CryptoMathService();
    
    #endregion
    
    
    #region Properties
    
    public RSAKey PublicKey => _publicKey;
    
    public RSAKey PrivateKey => _privateKey;
    
    #endregion
    
    
    #region Constructors
    
    public RSA(
        PrimalityTest primalityTestType,
        double targetPrimaryProbability,
        int primesBitLength,
        int keySizeInBits)
    {
        _keyGenerator = new RSAKeyGenerator(
            primalityTestType,
            targetPrimaryProbability, 
            primesBitLength,
            keySizeInBits);
        
        _keyGenerator.GenerateKeys(
            out _publicKey, 
            out _privateKey);
    }
    
    #endregion
    
    
    #region Methods
    
    public Memory<byte> Encrypt(Memory<byte> data)
    {
        return Encrypt(data, PrivateKey);
    }

    public Memory<byte> Decrypt(Memory<byte> data)
    {
        return Decrypt(data, PrivateKey);
    }
    
    public Memory<byte> Encrypt(Memory<byte> data, RSAKey key)
    {
        var dataBigInt = 
            new BigInteger(data.Span, true, false);
        
        return _cryptoMathService.ModPow(
                dataBigInt, 
                PublicKey.Exponent, 
                PublicKey.Modulus)
            .ToByteArray();
    }

    public Memory<byte> Decrypt(Memory<byte> data, RSAKey key)
    {
        var dataBigInt = 
            new BigInteger(data.Span, true, false);
        
        return _cryptoMathService.ModPow(
                dataBigInt, 
                key.Exponent, 
                key.Modulus)
            .ToByteArray();
    }
    
    #endregion
}