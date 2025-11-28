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
    
    private const double targetPrimaryProbability = 0.999;
    


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

    //todo: сделать общую папку Resources для всего проекта
    //todo: вынести в поля это. А лучше сделать файл настроек и брать оттуда
    //todo: сделать нормальные тесты картинок. Объединенные и с проверкой корректности
    [Test]
    public void EncryptDecryptImageFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.jpg";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.jpg";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.jpg";
        
        var rsa = _container.Resolve<Crypto.AsymmetricEncryption.RSA>();
        rsa.Encrypt(input, encrypted);
        rsa.Decrypt(encrypted, decrypted);
        Assert.True(true);
    }
   
    #endregion
}