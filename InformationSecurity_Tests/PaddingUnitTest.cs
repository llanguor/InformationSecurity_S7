using DryIoc;
using InformationSecurity_Tests.Infrastructure;
using InformationSecurity.SymmetricEncryption.CipherPadding.Paddings;
using Serilog;

namespace InformationSecurity_Tests;

[TestFixture]
public class PaddingUnitTest
{
    private readonly byte [] _data = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b1000011,0b1000011,
        0b1000011,0b1000011,0b1000011
    ];
    
    private Container? _container;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.RegisterInstance(8);
        _container.Register<ZerosPadding>();
        _container.Register<Iso10126Padding>();
        _container.Register<Pkcs7Padding>();
        _container.Register<AnsiX923Padding>();
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }

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
            $"ZerosPaddingTest Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
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
            $"ZerosPaddingTest Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
    
    [Test]
    public void Pkcs7PaddingApplyTest()
    {
        var result = 
            _container.Resolve<Pkcs7Padding>().Apply(_data);
        
        byte [] expectedResult = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011,
            0b1000011,0b1000011,0b1000011,0b00000101,
            0b00000101,0b00000101,0b00000101,0b00000101
        ];
        
        Log.Information(
            $"ZerosPaddingTest Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public void Pkcs7PaddingApplyFullBlockTest()
    {
        byte [] data =
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011
        ];
        
        byte [] expectedResult = 
        [
            0b01101101,0b1111111,0b10101010,0b01101110,
            0b10101111,0b1000011,0b1000011,0b1000011,
            0b00001000,0b00001000,0b00001000,0b00001000,
            0b00001000,0b00001000,0b00001000,0b00001000
        ];
        
        var result = 
            _container.Resolve<Pkcs7Padding>().Apply(data);

        
        Log.Information(
            $"ZerosPaddingTest Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            result);
    }
    
    [Test]
    public void Pkcs7PaddingRemoveTest()
    {
        var padding = _container.Resolve<Pkcs7Padding>();
        var result = 
            padding.Remove(
                padding.Apply(_data));
        
        Log.Information(
            $"ZerosPaddingTest Completed.\nResult:\n{Utils.BinaryToString(result)}Expected result:\n{Utils.BinaryToString(_data)}");
        
        CollectionAssert.AreEqual(
            _data, 
            result);
    }
}