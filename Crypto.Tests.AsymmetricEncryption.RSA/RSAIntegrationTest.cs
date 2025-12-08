using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace Crypto.Tests.AsymmetricEncryption.RSA;

public class RSAIntegrationTest
{
    #region Initialization
    
    private Container? _container;
    
    private const string ResourcesDirectoryPath = @"..\\..\\..\\Resources"; 
    
    private const Crypto.AsymmetricEncryption.RSA.RSAKeySize KeySize = 
        Crypto.AsymmetricEncryption.RSA.RSAKeySize.Bits1024;
    
    private const double TargetPrimaryProbability = 0.999;
    


    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        
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
    public void EncryptDecryptTextFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.txt";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.txt";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.txt";
        
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();
        rsa.Encrypt(input, encrypted);
        rsa.Decrypt(encrypted, decrypted);
       
        var inputBytes = File.ReadAllBytes(input);
        var decryptedBytes = File.ReadAllBytes(decrypted);

        Assert.Multiple(() =>
        {
            Assert.That(decryptedBytes, Has.Length.EqualTo(inputBytes.Length));
            Assert.That(inputBytes.SequenceEqual(decryptedBytes), Is.True);
        });
    }
    
    [Test]
    public void EncryptDecryptImageFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.jpg";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.jpg";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.jpg";
        
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();
        rsa.Encrypt(input, encrypted);
        rsa.Decrypt(encrypted, decrypted);
       
        var inputBytes = File.ReadAllBytes(input);
        var decryptedBytes = File.ReadAllBytes(decrypted);

        Assert.Multiple(() =>
        {
            Assert.That(decryptedBytes, Has.Length.EqualTo(inputBytes.Length));
            Assert.That(inputBytes.SequenceEqual(decryptedBytes), Is.True);
        });
    }
   
    #endregion
}