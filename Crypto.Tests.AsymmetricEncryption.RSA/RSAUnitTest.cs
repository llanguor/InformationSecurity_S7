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
        Crypto.AsymmetricEncryption.RSA.RSAKeySize.Bits1024;
    
    private const double targetPrimaryProbability = 0.999;

    private static readonly byte[] input =
    [
        0b11011010, 0b11011010, 0b11110101, 0b00111111,
        0b01010101, 0b11011010, 0b11110101, 0b00111111,
        0b01010101, 0b11011010, 0b11110101, 0b00111111,
        0b01010101, 0b11011010, 0b11110101, 0b11110101
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
    public void EncryptBlockDecryptBlockTest()
    {
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();
        var inputBlock = new byte[(int)KeySize/8];
        var expected = new byte[(int)KeySize/8];
        input.CopyTo(inputBlock, inputBlock.Length-input.Length);
        input.CopyTo(expected, expected.Length-input.Length);
       
        for (var i = 0; i < 50; ++i)
        {
            var encr = rsa.EncryptBlock(inputBlock, rsa.PublicKey);
            var decr = rsa.DecryptBlock(encr, rsa.PrivateKey);
            Assert.That(decr.ToArray(), Is.EqualTo(expected));
        }
    }
    
    [Test]
    public void EncryptBlockDecryptBlockShuffleKeysTest()
    {
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();
        var inputBlock = new byte[(int)KeySize/8];
        var expected = new byte[(int)KeySize/8];
        input.CopyTo(inputBlock, inputBlock.Length-input.Length);
        input.CopyTo(expected, expected.Length-input.Length);
       
        for (var i = 0; i < 50; ++i)
        {
            rsa.GenerateKeys();
            var encr = rsa.EncryptBlock(inputBlock, rsa.PublicKey);
            var decr = rsa.DecryptBlock(encr, rsa.PrivateKey);
            Assert.That(decr.ToArray(), Is.EqualTo(expected));
        }
    }
    
    [Test]
    public void EncryptDecryptTest()
    {
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();

        for (var i = 0; i < 50; ++i)
        {
            var encr = rsa.Encrypt(input);
            var decr = rsa.Decrypt(encr);
            
            Assert.That(decr.ToArray(), Is.EqualTo(input));
        }
    }
    
     
    [Test]
    public void EncryptDecryptShuffleKeysTest()
    {
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();

        for (var i = 0; i < 500; ++i)
        {
            rsa.GenerateKeys();
            var encr = rsa.Encrypt(input);
            var decr = rsa.Decrypt(encr);
            
            Assert.That(decr.ToArray(), Is.EqualTo(input));
        }
 
    }
    
    
    #endregion
}