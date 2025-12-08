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
        Crypto.AsymmetricEncryption.RSA.RSAKeySize.Bits1024;
    
    private const double TargetPrimaryProbability = 0.999;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        
        _container.Register<CryptoMathService>(Reuse.Singleton);
        _container.Register<MillerRabinPrimalityTest>();
        _container.RegisterInstance(new Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator(
            PrimalityTest.SolovayStrassen,
            KeySize,
            TargetPrimaryProbability));
        
        
        _container.RegisterInstance(new Crypto.AsymmetricEncryption.RSA(
            PrimalityTest.MillerRabin,
            RSAPaddingContext.RSAPaddingMode.PKCS1,
            KeySize,
            TargetPrimaryProbability));
            
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
        var math = 
            _container.Resolve<CryptoMathService>();
        
        for (var i = 0; i < 10; ++i)
        {
            generator.GenerateKeys(
                out var pbk,
                out var pvk);

            Assert.That(pvk.Exponent,
                Is.GreaterThan(math.Sqrt(pvk.Modulus, 4) / 3));

            var message = new BigInteger(123456789);
            var encrypted = BigInteger.ModPow(message, pbk.Exponent, pbk.Modulus);
            var decrypted = BigInteger.ModPow(encrypted, pvk.Exponent, pvk.Modulus);
            Assert.That(decrypted, Is.EqualTo(message));

            var signature = BigInteger.ModPow(message, pvk.Exponent, pvk.Modulus);
            var verified = BigInteger.ModPow(signature, pbk.Exponent, pbk.Modulus);
            Assert.That(verified, Is.EqualTo(message));
        }
    }

    [Test]
    public void GenerateDTest()
    {
        var generator = 
            _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();
       
        var action = new Action<BigInteger, BigInteger, BigInteger>(
            (value1, expected, e) =>
        {
            generator.CalculateD(
                out var result, 
                ref e,
                ref value1);
            
            Assert.That(
                result, 
                Is.EqualTo(expected));
        });
        
       action.Invoke(180, 53, 65537);
       action.Invoke(1800, -127+1800, 65537);
       action.Invoke(99999,  10304, 65537);
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
    
    #endregion
}