using System.Numerics;
using Crypto.AsymmetricEncryption;
using Crypto.AsymmetricEncryption.Contexts;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace TestProject1Crypto.Tests.AsymmetricEncryption.RSA;

public class PrimalityTestsTest
{
    #region Initialization
    
    private Container? _container;

    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        
        /*
        _container.RegisterInstance(new Crypto.AsymmetricEncryption.RSA(
            PrimalityTest.MillerRabin, 
            0.99, 
            128, 
            128));
            */
        
        _container.RegisterInstance(new Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator(
            PrimalityTest.MillerRabin,
            0.99,
            128,
            128));
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Tests
    
    [Test]
    public void RSAKeyGeneratorTest()
    {

    }
    
    [Test]
    public void RSAFourthRootTest()
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