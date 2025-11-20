using Crypto.AsymmetricEncryption;
using Crypto.AsymmetricEncryption.PrimalityTests;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace Crypto.Tests.AsymmetricEncryption;

public class PrimalityTestsTest
{
    #region Initialization
    
    private Container? _container;

    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.Register<FermatPrimalityTest>(Reuse.Singleton);
        _container.Register<MillerRabinPrimalityTest>(Reuse.Singleton);
        _container.Register<SolovayStrassenPrimalityTest>(Reuse.Singleton);
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Methods

    [Test]
    public void FermatPrimalityTest()
    {
        
    }
    
    
    [Test]
    public void MillerRabinPrimalityTest()
    {
        
    }
    
    
    [Test]
    public void SolovayStrassenPrimalityTest()
    {
        
    }
    
    #endregion
}