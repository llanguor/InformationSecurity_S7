namespace Crypto.Tests.SymmetricEncryption.RC4;
using Crypto.SymmetricEncryption.Contexts;
using Crypto.Tests.Infrastructure;
using DryIoc;

public class RC4IntegrationTest
{
    #region Initialization
    
    private Container? _container;

    private const string ResourcesDirectoryPath = @"..\\..\\..\\Resources"; 
    
    private readonly byte [] _key = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011
    ];
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.RegisterInstance(new Crypto.SymmetricEncryption.RC4(_key));
        _container.RegisterInstance(_key);
        _container.Register<Crypto.SymmetricEncryption.RC4>();
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Methods
    
    [Test]
    public void EncryptDecryptTextFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.txt";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.txt";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.txt";
        var rc4 = _container.Resolve<Crypto.SymmetricEncryption.RC4>();
        
        rc4.Encrypt(input, encrypted);
        rc4.Reset();
        rc4.Decrypt(encrypted, decrypted);

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

        var rc4 = _container.Resolve<Crypto.SymmetricEncryption.RC4>();
        
        rc4.Encrypt(input, encrypted);
        rc4.Reset();
        rc4.Decrypt(encrypted, decrypted);
        
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