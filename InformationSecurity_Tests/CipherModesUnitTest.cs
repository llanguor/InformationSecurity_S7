using DryIoc;
using DryIoc.ImTools;
using InformationSecurity_Tests.Infrastructure;
using InformationSecurity.SymmetricEncryption.CipherMode.Base;
using InformationSecurity.SymmetricEncryption.CipherMode.Modes;
using Serilog;

namespace InformationSecurity_Tests;

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

        _container.Register<CbcMode>();
        _container.Register<CfbMode>();
        _container.Register<CtrMode>();
        _container.Register<EcbMode>();
        _container.Register<OfbMode>();
        _container.Register<PcbcMode>();
        _container.Register<RandomDeltaMode>();
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    #region EcbMode

    [Test]
    public void EcbModeEncryptionTest()
    {
        byte [] expectedResult = 
        [
            0b11111110,0b11111110,0b11111110,0b11111110,
            0b00000001,0b00000001,0b00000001,0b00000001
        ];
        
        var result = _data.ToArray();
        _container.Resolve<EcbMode>()
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
        var mode = _container.Resolve<EcbMode>();
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
        await _container.Resolve<EcbMode>()
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
        var mode = _container.Resolve<EcbMode>();
        await mode.DecryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            result, 
            _data);
    }
    
    #endregion
    
    #region CbcMode
    
    
    [Test]
    public void CbcModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CbcMode>();
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
        var mode = _container.Resolve<CbcMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region CfbMode
    
    [Test]
    public void CfbModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<CfbMode>();
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
        var mode = _container.Resolve<CfbMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region OfbMode
    
    [Test]
    public void OfbModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<OfbMode>();
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
        var mode = _container.Resolve<OfbMode>();
        await mode.EncryptAsync(result);
        await mode.DecryptAsync(result);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region PcbcMode
    
    [Test]
    public void PcbcModeDecryptionTest()
    { 
        var result = _data.ToArray();
        var mode = _container.Resolve<PcbcMode>();
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
        var mode = _container.Resolve<PcbcMode>();
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