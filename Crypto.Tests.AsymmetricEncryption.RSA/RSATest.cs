using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace Crypto.Tests.AsymmetricEncryption.RSA;

public class RSATest
{
    #region Initialization
    
    private Container? _container;

    private const Crypto.AsymmetricEncryption.RSA.RSAKeySize KeySize = 
        Crypto.AsymmetricEncryption.RSA.RSAKeySize.Bits2048;
    
    private const double targetPrimaryProbability = 0.999;

    private static readonly byte[] input =
    [
        0b01010101, 0b11011010, 0b11110101, 0b00111111,
        0b01010101, 0b11011010, 0b11110101, 0b00111111,
        0b01010101, 0b11011010, 0b11110101, 0b00111111,
        0b01010101, 0b11011010, 0b11110101, 0b00111111
    ];


    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        
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
    public void EncryptDecryptTest()
    {
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();
        
        var encr = rsa.EncryptBlock(input, rsa.PublicKey);
        var decr = rsa.DecryptBlock(encr, rsa.PrivateKey);
        
        Assert.That(decr.ToArray(), Is.EqualTo(input));
        
    }
    
    
    #endregion
}