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
    
    
    #endregion
}