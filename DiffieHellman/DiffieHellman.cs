using System.Numerics;
using Crypto.AsymmetricEncryption;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;
using Crypto.KeyExchange.Base.Interfaces;

namespace Crypto.KeyExchange;

public class DiffieHellman :
    IDiffieHellman
{
    #region Constructors
    
    public DiffieHellman(
        int keySize,
        PrimalityTest primalityTestType,
        double targetPrimaryProbability = 0.999)
    {
        KeySize = keySize;
        _targetPrimaryProbability =
            targetPrimaryProbability;
        
        _primalityTest =
            new PrimalityTestContext(primalityTestType);
        
        GenerateInitValues();
        GenerateKeyPair();
    }

    public DiffieHellman(
        int keySize, 
        PrimalityTest primalityTestType,
        BigInteger @base, 
        BigInteger module,
        double targetPrimaryProbability = 0.999)
    {
        KeySize = keySize;
        Base = @base;
        Module = module;
        _targetPrimaryProbability =
            targetPrimaryProbability;
        
        _primalityTest =
            new PrimalityTestContext(primalityTestType);

        GenerateKeyPair();
    }

    #endregion
    
    
    #region Fields
    
    private readonly CryptoMathService _cryptoMathService = new ();

    private readonly int _keySize;
    
    private readonly IPrimalityTest _primalityTest;

    private readonly double _targetPrimaryProbability;
    
    #endregion
    

    #region Properties

    public int KeySize
    {
        get => _keySize;
        private init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
            _keySize = value;
        }
    }
    
    public BigInteger Base { get; private set; }
    
    public BigInteger Module { get; private set; }

    public BigInteger PublicKey { get; private set; }
    
    private BigInteger PrivateKey { get; set; }
    
    public BigInteger SharedSecret { get; private set; }
    
    #endregion
    
    
    #region Public Methods
    
    public void GenerateInitValues()
    {
        Module = GeneratePrime(KeySize);
        Base = FindMinimalPrimitive(Module);
    }

    public void GenerateKeyPair()
    {
        PrivateKey = GenerateBigInteger(_keySize);
        PublicKey = 
            _cryptoMathService.ModPow(
            Base, 
            PrivateKey, 
            Module);
    }

    public void ComputeSharedSecret(BigInteger externalPublicKey)
    {
        if (PrivateKey == default ||
            PublicKey == default)
            throw new ArgumentException();
        
        SharedSecret = 
            _cryptoMathService.ModPow(
            externalPublicKey, 
            PrivateKey, 
            Module);
    }
    
    #endregion
    
    
    #region Private Methods
    
    private BigInteger GenerateBigInteger(int size)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);

        var bytes = new byte[size];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        
        var result = new BigInteger(
            bytes.AsSpan(), 
            isUnsigned: true,
            isBigEndian: false);
        
        return result;
    }
    
    private BigInteger GeneratePrime(int size)
    {
        if (size <= 0)
            throw new ArgumentOutOfRangeException(nameof(size));
        
        var bytes = new byte[size];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        
        var result = new BigInteger(
            bytes.AsSpan(), 
            isUnsigned: true,
            isBigEndian: false);
            
            
        int[] increments = 
        [
            2, 2, 4
        ];
            
        var sign = 
            bytes[^1] == 0xFF ? -1 : 1;

        for (var i = 0; ; ++i)
        {
            result += sign * increments[i % 3];
            var isPrime = 
                _primalityTest.IsPrimary(result, _targetPrimaryProbability);

            if (isPrime == PrimalityResult.Prime)
            {
                return result;
            }
        }
    }
    
    private BigInteger FindMinimalPrimitive(
        BigInteger prime)
    {
        //todo: Implementation
        return 5;
    }
    
    #endregion
}