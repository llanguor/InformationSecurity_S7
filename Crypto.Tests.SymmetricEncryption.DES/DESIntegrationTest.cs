using Crypto.SymmetricEncryption.Contexts;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace Crypto.Tests.DES;

public class DESIntegrationTest
{
    #region Initialization
    
    private Container? _container;

    private const string ResourcesDirectoryPath = @"..\\..\\..\\Resources"; 
    
    private readonly byte [] _data = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011
    ];

    private readonly byte [] _key = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011
    ];
    
    private readonly byte [] _initializationVector = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011
    ];

    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.RegisterInstance<SymmetricEncryption.SymmetricEncryption>(
            new SymmetricEncryption.DES(
                _key,
                SymmetricPaddingContext.SymmetricPaddingMode.Zeros,
                SymmetricModeContext.SymmetricMode.CFB,
                _initializationVector));
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Methods
    
    [Test]
    public void EncryptTextFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.txt";
        const string output = $"{ResourcesDirectoryPath}\\encrypted.txt";
        var des = _container.Resolve<SymmetricEncryption.SymmetricEncryption>();
        des.Encrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void DecryptTextFileTest()
    { 
        const string input = $"{ResourcesDirectoryPath}\\encrypted.txt";
        const string output = $"{ResourcesDirectoryPath}\\decrypted.txt";
        var des = _container.Resolve<SymmetricEncryption.SymmetricEncryption>();
        des.Decrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void EncryptDecryptTextFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.txt";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.txt";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.txt";
        var des = _container.Resolve<SymmetricEncryption.SymmetricEncryption>();
        des.Encrypt(input, encrypted);
        des.Decrypt(encrypted, decrypted);
        Assert.True(true);
    }
    
    [Test]
    public void EncryptImageFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.jpg";
        const string output = $"{ResourcesDirectoryPath}\\encrypted.jpg";
        var des = _container.Resolve<SymmetricEncryption.SymmetricEncryption>();
        des.Encrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void DecryptImageFileTest()
    { 
        const string input = $"{ResourcesDirectoryPath}\\encrypted.jpg";
        const string output = $"{ResourcesDirectoryPath}\\decrypted.jpg";
        var des = _container.Resolve<SymmetricEncryption.SymmetricEncryption>();
        des.Decrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void EncryptDecryptImageFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.jpg";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.jpg";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.jpg";
        var des = _container.Resolve<SymmetricEncryption.SymmetricEncryption>();
        des.Encrypt(input, encrypted);
        des.Decrypt(encrypted,decrypted);
        Assert.True(true);
    }

    #endregion
}