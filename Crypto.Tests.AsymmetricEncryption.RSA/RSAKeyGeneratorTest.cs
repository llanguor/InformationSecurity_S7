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
        for (var i = 0; i < 10; ++i)
        {
            var generator =
                _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();

            generator.GenerateKeys(
                out var pbk,
                out var pvk);

            Assert.That(pvk.Exponent,
                Is.GreaterThan(generator.FourthRoot(pvk.Modulus) / 3));

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
       
        var action = new Action<BigInteger, BigInteger>(
            (value1, expected) =>
        {
            generator.CalculateD(
                out var result, 
                ref value1);
            
            Assert.That(
                result, 
                Is.EqualTo(expected));
        });

        const int e = Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator.E;
       action.Invoke(180, 53);
       action.Invoke(1800, -127+1800);
       action.Invoke(99999,  10304);
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