using DryIoc;
using InformationSecurity_Tests.Infrastructure;
using InformationSecurity.SymmetricEncryption;
using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Enum;
using InformationSecurity.SymmetricEncryption.CipherPadding.Enum;
using InformationSecurity.SymmetricEncryption.Des;

namespace InformationSecurity_Tests;

public class DesIntegrationTest
{
    #region Initialization
    
    private Container? _container;

    private const string ResourcesDirectoryPath = @"..\\..\\..\\Resources\\Des"; 
    
    private readonly byte [] _data = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011
    ];

    private readonly byte [] _key = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011,
        0b1000011,0b1000011,0b1000011
    ];

    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.RegisterInstance<SymmetricEncryption>(
            new Des(
                _key,
                CipherPadding.Zeros,
                CipherMode.Ecb));
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }

    #endregion
    
    
    #region Tests
    
    [Test]
    public void EncryptFileTest()
    {
        const string input = $"{ResourcesDirectoryPath}\\input.txt";
        const string output = $"{ResourcesDirectoryPath}\\encrypted.txt";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Encrypt(input, output);
        Assert.True(true);
    }
    
    [Test]
    public void DecryptFileTest()
    { 
        const string input = $"{ResourcesDirectoryPath}\\encrypted.txt";
        const string output = $"{ResourcesDirectoryPath}\\decrypted.txt";
        var des = _container.Resolve<SymmetricEncryption>();
        des.Decrypt(input, output);
        Assert.True(true);
    }
    
    #endregion
}