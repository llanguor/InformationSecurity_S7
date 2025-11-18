using Crypto.SymmetricEncryption.Modes;
using Crypto.Tests.Infrastructure;
using DryIoc;
using Serilog;

namespace Crypto.Tests.SymmetricEncryption;

public class CipherModesUnitTest
{
    #region Initialization
    
    private const int BlockSize = 8;
    
    private readonly byte [] _data = 
    [
        0b11111111,0b11111111,0b11111111,0b11111111,
        0b00000000,0b00000000,0b00000000,0b00000000
    ];
    
    private readonly byte [] _initializationVector = 
    [
        0b11111111, 0b00000000,0b11111111,0b11111111,
        0b00000000,0b11111111,0b00000000,0b11111111,
    ];
    
    private Container? _container;

    private static void BlockTransformation(Memory<byte> data)
    {
        //last bits inversion
        var span = data.Span;
        for (var i = 0; i < span.Length; i++)
        {
            span[i] ^= 0x01;
        }
    }

    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        
        _container.RegisterInstance(BlockTransformation);
        _container.RegisterInstance(BlockSize);
        _container.RegisterInstance(_initializationVector);

        _container.Register<CBCMode>();
        _container.Register<CFBMode>();
        _container.Register<CTRMode>();
        _container.Register<ECBMode>();
        _container.Register<OFBMode>();
        _container.Register<PCBCMode>();
        _container.Register<RandomDeltaMode>();
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    #region ECBMode

    [Test]
    public void EcbModeEncryptionTest()
    {
        byte [] expectedResult = 
        [
            0b11111110,0b11111110,0b11111110,0b11111110,
            0b00000001,0b00000001,0b00000001,0b00000001
        ];
        
        var result = _data.ToArray();
        _container.Resolve<ECBMode>()
            .Encrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }

    
    [Test]
    public void EcbModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<ECBMode>();
        mode.Encrypt(result);
        mode.Decrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            result, 
            _data);
    }
    
    
    [Test]
    public async Task EcbModeEncryptionAsyncTest()
    {
        byte [] expectedResult = 
        [
            0b11111110,0b11111110,0b11111110,0b11111110,
            0b00000001,0b00000001,0b00000001,0b00000001
        ];
        
        var result = _data.ToArray();
        await _container.Resolve<ECBMode>()
            .EncryptAsync(result);

        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public async Task EcbModeDecryptionAsyncTest()
    {
        var result = _data.ToArray();
        var mode = _container.Resolve<ECBMode>();
        await mode.DecryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            result, 
            _data);
    }
    
    #endregion
    
    #region CBCMode
    
    
    [Test]
    public void CbcModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CBCMode>();
        mode.Encrypt(result);
        mode.Decrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    [Test]
    public async Task CbcModeDecryptionAsyncTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CBCMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region CFBMode
    
    [Test]
    public void CfbModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CFBMode>();
        mode.Encrypt(result);
        mode.Decrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    [Test]
    public async Task CfbModeDecryptionAsyncTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CFBMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region OFBMode
    
    [Test]
    public void OfbModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<OFBMode>();
        mode.Encrypt(result);
        mode.Decrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    [Test]
    public async Task OfbModeDecryptionAsyncTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<OFBMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region PCBCMode
    
    [Test]
    public void PcbcModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<PCBCMode>();
        mode.Encrypt(result);
        mode.Decrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    [Test]
    public async Task PcbcModeDecryptionAsyncTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<PCBCMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    
    #region PCBCMode
    
    [Test]
    public void RdModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<RandomDeltaMode>();
        mode.Encrypt(result);
        mode.Decrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    [Test]
    public async Task RdModeDecryptionAsyncTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<RandomDeltaMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region PCBCMode
    
    [Test]
    public void CtrModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CTRMode>();
        mode.Encrypt(result);
        mode.Decrypt(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    [Test]
    public async Task CtrModeDecryptionAsyncTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CTRMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
}