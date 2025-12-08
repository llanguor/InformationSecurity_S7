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
        BigInteger a = -14124;
        BigInteger b = -3951;
        BigInteger expected = 3;
        
        var result = 
            _container.Resolve<CryptoMathService>()
                .CalculateGcdEuclidean(a,b);
        
        Assert.That(result, Is.EqualTo(expected));
    }
    
    [Test]
    public void CalculateGcdEuclideanExtendedTest()
    {
        BigInteger a = -14124;
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
    
    [Test]
    public void CalculateLegendreSymbolTest()
    {
        var mService = _container.Resolve<CryptoMathService>();
        
        Assert.Multiple(() =>
        {
            Assert.That(
                mService.CalculateLegendreSymbol(3, 5), 
                Is.EqualTo(-1));
            Assert.That(
                mService.CalculateLegendreSymbol(7, 23), 
                Is.EqualTo(-1));
            Assert.That(
                mService.CalculateLegendreSymbol(-7, 23), 
                Is.EqualTo(1));
            Assert.That(
                mService.CalculateLegendreSymbol(-9, 23), 
                Is.EqualTo(-1));
        });
    }

    [Test]
    public void CalculateJacobiSymbolTest()
    {
        var mService = _container.Resolve<CryptoMathService>();

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() =>
                mService.CalculateJacobiSymbol(5, 10));
            Assert.That(
                mService.CalculateJacobiSymbol(1, 23),
                Is.EqualTo(1));
            Assert.That(
                mService.CalculateJacobiSymbol(-1, 23),
                Is.EqualTo(1));
            Assert.That(
                mService.CalculateJacobiSymbol(17, 21),
                Is.EqualTo(1));
            Assert.That(
                mService.CalculateJacobiSymbol(19, 25),
                Is.EqualTo(1));
            Assert.That(
                mService.CalculateJacobiSymbol(3, 5),
                Is.EqualTo(-1));
            Assert.That(
                mService.CalculateJacobiSymbol(5, 15),
                Is.EqualTo(0));
            Assert.That(
                mService.CalculateJacobiSymbol(18, 21),
                Is.EqualTo(0));
        });
    }

    [Test]
    public void FourthRootTest()
    {
        var service =
            _container.Resolve<CryptoMathService>();
        
        var rnd = new Random();
        
        for (var i = 0; i < 10000; ++i)
        {
            var expected = rnd.NextInt64(1, long.MaxValue);
            var powered = BigInteger.Pow(expected, 4);
            var result = service.Sqrt(powered, 4);
            
            Assert.That(
                (long)result, 
                Is.EqualTo(expected), 
                $"Failed for value: {expected}");
        }
    }

    [Test]
    public void RootTest()
    {
        var math = _container.Resolve<CryptoMathService>();
        var rnd = new Random();
        var numbersAfterPoint = 9;
        
        for (var i = 0; i < 100; ++i)
        {
            var value = rnd.NextInt64(1, long.MaxValue);
            var root = Math.Sqrt(value);
            
            var integerExpected = Math.Truncate(root);
            var fractionalExpected = 
                new BigInteger(Math.Floor(
                    (root - Math.Truncate(root)) * 
                    Math.Pow(10, numbersAfterPoint)));
            
            var integerResult = math.Sqrt(
                value,
                out var fractionalResult
                , numbersAfterPoint);
            
            var isEquals = 
                math.AreFractionalsApproximatelyEqual(
                    fractionalExpected, 
                    fractionalResult, 
                    0.001);
            
            Assert.That(
                (double)integerResult,
                Is.EqualTo(integerExpected), 
                $"Failed integer part for value: {value}");
            
            Assert.That(
                isEquals, 
                Is.EqualTo(true),
                $"Failed fractional for value: {value}\nExpected (scaled): {fractionalExpected}\nBut was: {fractionalResult}");

        }
    }
    
    #endregion
}