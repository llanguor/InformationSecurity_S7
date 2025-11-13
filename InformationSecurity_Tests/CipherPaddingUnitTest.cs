using DryIoc;
using InformationSecurity_Tests.Infrastructure;
using InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;
using Serilog;

namespace InformationSecurity_Tests;

[TestFixture]
public class CipherPaddingUnitTest
{
    #region Initialization
    
    private const int BlockSize = 8;
        
    private readonly byte [] _data = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011,
        0b1000011,0b1000011,0b1000011
    ];
    
    private readonly byte [] _dataFullBlock = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011
    ];
    
    private Container? _container;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.RegisterInstance(8);
        _container.Register<ZerosPadding>();
        _container.Register<ISO10126Padding>();
        _container.Register<PKCS7Padding>();
        _container.Register<ANSIX923Padding>();
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }

    #endregion
    
    #region ZerosPadding
    
    [Test]
    public void ZerosPaddingApplyTest()
    {
        var result = 
            _container.Resolve<ZerosPadding>().Apply(_data);
        
        byte [] expectedResult = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011,
            0b1000011,0b1000011,0b1000011,0b00000000,
            0b00000000,0b00000000,0b00000000,0b00000000
        ];
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public void ZerosPaddingRemoveTest()
    {
        var padding = _container.Resolve<ZerosPadding>();
        var result = 
            padding.Remove(
            padding.Apply(_data));
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region PKCS7Padding
    
    [Test]
    public void Pkcs7PaddingApplyTest()
    {
        var result = 
            _container.Resolve<PKCS7Padding>().Apply(_data);
        
        byte [] expectedResult = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011,
            0b1000011,0b1000011,0b1000011,0b00000101,
            0b00000101,0b00000101,0b00000101,0b00000101
        ];
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public void Pkcs7PaddingApplyFullBlockTest()
    {
        byte [] expectedResult = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011,
            0b00001000,0b00001000,0b00001000,0b00001000,
            0b00001000,0b00001000,0b00001000,0b00001000
        ];
        
        var result = 
            _container.Resolve<PKCS7Padding>().Apply(_dataFullBlock);

        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public void Pkcs7PaddingRemoveTest()
    {
        var padding = _container.Resolve<PKCS7Padding>();
        var result = 
            padding.Remove(
                padding.Apply(_data));
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region ANSIX923Padding
    
    [Test]
    public void AnsiX923PaddingApplyTest()
    {
        var result = 
            _container.Resolve<ANSIX923Padding>().Apply(_data);
        
        byte [] expectedResult = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011,
            0b1000011,0b1000011,0b1000011,0b00000000,
            0b00000000,0b00000000,0b00000000,0b00000101
        ];
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public void AnsiX923PaddingApplyFullBlockTest()
    {
        byte [] expectedResult = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011,
            0b00000000,0b00000000,0b00000000,0b00000000,
            0b00000000,0b00000000,0b00000000,0b00001000
        ];
        
        var result = 
            _container.Resolve<ANSIX923Padding>().Apply(_dataFullBlock);

        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public void AnsiX923PaddingRemoveTest()
    {
        var padding = _container.Resolve<ANSIX923Padding>();
        var result = 
            padding.Remove(
                padding.Apply(_data));
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
    
    #region ISO10126Padding
    
    [Test]
    public void Iso10126PaddingApplyTest()
    {
        var result = 
            _container.Resolve<ISO10126Padding>().Apply(_data);
        
        var inputBlockSpan = _data.AsSpan();
        var outputBlockSpan = result.AsSpan(0, inputBlockSpan.Length);
        
        var expectedSize = BlockSize * (_data.Length / BlockSize + 1);
        var outputSize = result.Length;
        
        var expectedLastByteData = expectedSize - _data.Length;
        var outputLastByteData = (int)result[^1];


        if (outputSize == expectedSize &&
            expectedLastByteData == outputLastByteData &&
            inputBlockSpan.SequenceEqual(outputBlockSpan))
        {
            Log.Information(
                $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}");
            Assert.That(true);
        }
        else
        {
            Log.Information(
                $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}");
            Assert.That(false);
        }
    }
    
    [Test]
    public void Iso10126PaddingApplyFullBlockTest()
    {
        var result = 
            _container.Resolve<ISO10126Padding>().Apply(_dataFullBlock);
        
        var inputBlockSpan = _dataFullBlock.AsSpan();
        var outputBlockSpan = result.AsSpan(0, inputBlockSpan.Length);
        
        var expectedSize = BlockSize * (_dataFullBlock.Length / BlockSize + 1);
        var outputSize = result.Length;
        
        var expectedLastByteData = expectedSize - _dataFullBlock.Length;
        var outputLastByteData = (int)result[^1];


        if (outputSize == expectedSize &&
            expectedLastByteData == outputLastByteData &&
            inputBlockSpan.SequenceEqual(outputBlockSpan))
        {
            Log.Information(
                $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}");

            Assert.That(true);
        }
        else
        {
            Log.Information(
                $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}");

            Assert.That(false);
        }
    }
    
    [Test]
    public void Iso10126PaddingRemoveTest()
    {
        var padding = _container.Resolve<ISO10126Padding>();
        var result = 
            padding.Remove(
                padding.Apply(_data));
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    #endregion
}