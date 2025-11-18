using Crypto.SymmetricEncryption;
using Crypto.Tests.Infrastructure;
using DryIoc;
using Serilog;

namespace Crypto.Tests.SymmetricEncryption;

public class FeistelNetworkTests
{
    #region Initialization
    
    private readonly byte[] _key = 
    [
        0b01101101, 0b11111111, 0b10101010, 0b01101110,
        0b10101111, 0b10000111, 0b01101010, 0b10011110
    ];
    
    private Container? _container;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        var keySchedule = new DESKeySchedule();
        var roundFunction = new DESRoundFunction();
        var feistel = 
            new FeistelNetwork(
                new DESKeySchedule(),
                new DESRoundFunction(),
                _key,
                16);
        
        _container = new Container();
        _container.RegisterInstance(keySchedule);
        _container.RegisterInstance(roundFunction);
        _container.RegisterInstance(feistel);
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    #region Crypto.Tests.DES1
    
    [Test]
    public void EncryptTest()
    {
        byte[] data = 
        [
            0b01101101, 0b11111110, 0b10101010, 0b01101110,
            0b10101111, 0b10000110, 0b01101010, 0b10011110
        ];
        
        byte[] expectedResult = 
        [
            0b10111000, 0b10000110, 0b01101001, 0b10100000, 
            0b11100000, 0b10110111, 0b10001100, 0b01001010
        ];
        
        _container.Resolve<FeistelNetwork>()
            .Encrypt(data);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(data)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            data);
    }
    
    [Test]
    public void DecryptTest()
    {
        byte[] data = 
        [
            0b10111000, 0b10000110, 0b01101001, 0b10100000, 
            0b11100000, 0b10110111, 0b10001100, 0b01001010
        ];
        
        byte[] expectedResult = 
        [
            0b01101101, 0b11111110, 0b10101010, 0b01101110,
            0b10101111, 0b10000110, 0b01101010, 0b10011110
        ];
        
        _container.Resolve<FeistelNetwork>()
            .Decrypt(data);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(data)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            data);
    }

    [Test]
    public void EncryptDecryptTest()
    {
        byte[] data = 
        [
            0b10111000, 0b10000110, 0b01101001, 0b10100000, 
            0b11100000, 0b10110111, 0b10001100, 0b01001010
        ];

        byte[] expectedResult =
        [
            0b10111000, 0b10000110, 0b01101001, 0b10100000, 
            0b11100000, 0b10110111, 0b10001100, 0b01001010
        ];

        var feistel = _container.Resolve<FeistelNetwork>();
        feistel.Encrypt(data);
        feistel.Decrypt(data);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(data)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            data);
    }
    
    #endregion
}