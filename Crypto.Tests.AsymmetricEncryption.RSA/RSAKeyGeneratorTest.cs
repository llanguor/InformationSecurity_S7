using System.Numerics;
using Crypto.AsymmetricEncryption;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;
using Crypto.AsymmetricEncryption.PrimalityTests;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace Crypto.Tests.AsymmetricEncryption.RSA;

public class RSAKeyGeneratorTest
{
    #region Initialization
    
    private Container? _container;

    private const Crypto.AsymmetricEncryption.RSA.RSAKeySize KeySize  = 
        Crypto.AsymmetricEncryption.RSA.RSAKeySize.Bits2048;
    
    private const double targetPrimaryProbability = 0.999;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        
        _container.Register<MillerRabinPrimalityTest>();
        _container.RegisterInstance(new Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator(
            PrimalityTest.SolovayStrassen,
            KeySize,
            targetPrimaryProbability));
        
        
        _container.RegisterInstance(new Crypto.AsymmetricEncryption.RSA(
            PrimalityTest.MillerRabin,
            RSAPaddingContext.RSAPaddingMode.PKCS1,
            KeySize,
            targetPrimaryProbability));
            
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Tests

    [Test]
    public void GenerateKeysTest()
    {
        var generator = 
            _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();
        
        generator.GenerateKeys(
            out var pbk,
            out var pvk);
        
        Assert.That(pvk.Exponent, 
            Is.GreaterThan(generator.FourthRoot(pvk.Modulus)/3));
        
        var message = new BigInteger(123456789);
        var encrypted = BigInteger.ModPow(message, pbk.Exponent, pbk.Modulus);
        var decrypted = BigInteger.ModPow(encrypted, pvk.Exponent, pvk.Modulus);
        Assert.That(decrypted, Is.EqualTo(message));
        
        var signature = BigInteger.ModPow(message, pvk.Exponent, pvk.Modulus);
        var verified = BigInteger.ModPow(signature, pbk.Exponent, pbk.Modulus);
        Assert.That(verified, Is.EqualTo(message));
    }

    [Test]
    public void GenerateDTest()
    {
        var generator = 
            _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();
       
        var action = new Action<BigInteger, BigInteger, BigInteger>(
            (value1, value2, expected) =>
        {
            generator.CalculateD(
                out var result, 
                ref value1, 
                ref value2);
            
            Assert.That(
                result, 
                Is.EqualTo(expected));
        });
      
       action.Invoke(180, 150, 1);
       action.Invoke(1800, 23933, -10597+23933);
       action.Invoke(1800, 134, -30+134);
       action.Invoke(99999, 23933, 7471);
    }

    [Test]
    public void GenerateETest()
    {
        var generator = 
            _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();

        for (var i = 0; i < 10; ++i)
        {
            generator.GeneratePrime(out var p, 0b10, 2);
            generator.GeneratePrime(out var q, 0b11, 2);
            
            var n = p * q;
            var eulerN = (p - 1) * (q - 1);
            var minD = generator.FourthRoot(n) / 3;
            
            generator.GenerateE(out var e, ref eulerN); 
                
            var isCoprime = new CryptoMathService()
                .CalculateGcdEuclidean(e, n) == 1;
            
            Assert.That(
                isCoprime, 
                Is.EqualTo(true));
        }
    }
    
    [Test]
    public void GeneratePrimeTest()
    {
        var generator = _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();
        var primalityTest = _container.Resolve<MillerRabinPrimalityTest>();
        var testProb = 0.9999;
        
        for (var i = 0; i < 20; ++i)
        {
            generator.GeneratePrime(out var p, 0b10, 2);
            
            Assert.That(
                primalityTest.IsPrimary(p, testProb), 
                Is.EqualTo(PrimalityResult.Prime));
        }
    }
    
    [Test]
    public void FourthRootTest()
    {
        var generator = _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();
        var rnd = new Random();
        
        for (var i = 0; i < 10000; ++i)
        {
            var expected = rnd.NextInt64(1, long.MaxValue);
            var powered = BigInteger.Pow(expected, 4);
            var result = generator.FourthRoot(powered);
            
            Assert.That(
                (long)result, 
                Is.EqualTo(expected), 
                $"Failed for value: {expected}");
        }
     
    }
    
    
    #endregion
}