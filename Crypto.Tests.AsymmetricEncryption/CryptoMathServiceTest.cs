using System.Numerics;
using Crypto.AsymmetricEncryption;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace Crypto.Tests.AsymmetricEncryption;

public class CryptoMathServiceTest
{
    #region Initialization
    
    private Container? _container;

    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.Register<CryptoMathService>(
            Reuse.Singleton);
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Methods

    [Test]
    public void ModPowTest()
    {
        BigInteger baseValue = 19;
        BigInteger exponent = 123;
        BigInteger module = 2000;
        BigInteger expected = 1259;
        
        var result = 
            _container.Resolve<CryptoMathService>()
                .ModPow(
                    baseValue,
                    exponent, 
                    module);
        
        Assert.That(result, Is.EqualTo(expected));
    }
    
    [Test]
    public void CalculateGcdEuclideanTest()
    {
        BigInteger a = 14124;
        BigInteger b = 3951;
        BigInteger expected = 3;
        
        var result = 
            _container.Resolve<CryptoMathService>()
                .CalculateGcdEuclidean(a,b);
        
        Assert.That(result, Is.EqualTo(expected));
    }
    
    [Test]
    public void CalculateGcdEuclideanExtendedTest()
    {
        BigInteger a = 14124;
        BigInteger b = 3951;
        BigInteger expectedGcd = 3;
        
        _container.Resolve<CryptoMathService>()
            .CalculateGcdEuclidean(
                a,
                b,
                out var gcd, 
                out var x, 
                out var y);
        
        Assert.Multiple(() =>
        {
            Assert.That(gcd, Is.EqualTo(expectedGcd));
            Assert.That(a * x + b * y, Is.EqualTo(gcd));
        });
    }

    #endregion
}