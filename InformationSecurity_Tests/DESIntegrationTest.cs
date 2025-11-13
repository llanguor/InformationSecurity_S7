using DryIoc;
using InformationSecurity_Tests.Infrastructure;
using InformationSecurity.SymmetricEncryption;
using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Enum;
using InformationSecurity.SymmetricEncryption.CipherPadding.Enum;
using InformationSecurity.SymmetricEncryption.Des;

namespace InformationSecurity_Tests;

public class DESIntegrationTest
{
    #region Initialization
    
    private Container? _container;

    private const string ResourcesDirectoryPath = @"..\\..\\..\\Resources\\DES"; 
    
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
        _container.RegisterInstance<SymmetricEncryption>(
            new DES(
                _key,
                CipherPadding.Zeros,
                CipherMode.CFB,
                _initializationVector));
        // error: CFB (image)
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Tests
    
    [Test]
    public void EncryptTextFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.txt";
        const string output = $"{ResourcesDirectoryPath}\\encrypted.txt";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Encrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void DecryptTextFileTest()
    { 
        const string input = $"{ResourcesDirectoryPath}\\encrypted.txt";
        const string output = $"{ResourcesDirectoryPath}\\decrypted.txt";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Decrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void EncryptDecryptTextFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.txt";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.txt";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.txt";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Encrypt(input, encrypted);
        des.Decrypt(encrypted, decrypted);
        Assert.True(true);
    }

    
    [Test]
    public void EncryptImageFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.jpeg";
        const string output = $"{ResourcesDirectoryPath}\\encrypted.jpeg";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Encrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void DecryptImageFileTest()
    { 
        const string input = $"{ResourcesDirectoryPath}\\encrypted.jpeg";
        const string output = $"{ResourcesDirectoryPath}\\decrypted.jpeg";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Decrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void EncryptDecryptImageFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.jpeg";
        const string encrypted = $"{ResourcesDirectoryPath}\\encrypted.jpeg";
        const string decrypted = $"{ResourcesDirectoryPath}\\decrypted.jpeg";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Encrypt(input, encrypted);
        des.Decrypt(encrypted,decrypted);
        Assert.True(true);
    }

    #endregion
}