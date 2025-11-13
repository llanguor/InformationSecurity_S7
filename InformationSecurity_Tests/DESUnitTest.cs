using System.Reflection;
using DryIoc;
using InformationSecurity_Tests.Infrastructure;
using InformationSecurity.SymmetricEncryption.CipherMode.Enum;
using InformationSecurity.SymmetricEncryption.CipherPadding.Enum;
using InformationSecurity.SymmetricEncryption.Des;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;
using Serilog;

namespace InformationSecurity_Tests;

public class DesTests
{
    #region Initialization
    
    private readonly byte [] _key = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b01101010,0b10011110
    ];
    
    private readonly byte [] _initVector = 
    [
        0b01101101,0b1111111,0b10101010,0b01101110,
        0b10101111,0b1000011,0b01101010,0b10011110
    ];
    
    private Container? _container;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.Register<IKeySchedule, DESKeySchedule>();
        _container.Register<IRoundFunction, DESRoundFunction>();
        _container.RegisterInstance(
            new DES(
                _key,
                CipherPadding.Iso10126,
                CipherMode.CBC,
                _initVector
            ));
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    #region KeySchedule
    
    [Test]
    public void DesKeyScheduleTest()
    {
        byte [][] expectedResult = 
        [
            [0b11010111, 0b10111110, 0b00000100, 0b00101011, 0b11111111, 0b10011111], 
            [0b10100000, 0b00101101, 0b01101111, 0b10101110, 0b00111111, 0b01111011],
            [0b11100001, 0b01100110, 0b00110101, 0b10111111, 0b11111011, 0b01110110], 
            [0b11000101, 0b10011111, 0b10110000, 0b01110101, 0b11001111, 0b11110010], 
            [0b11010110, 0b10110010, 0b11110011, 0b11011101, 0b10101100, 0b01011111], 
            [0b10111111, 0b11010110, 0b01000010, 0b11101111, 0b11110110, 0b11011100], 
            [0b01101010, 0b01010011, 0b11001110, 0b00111001, 0b11110111, 0b11101111], 
            [0b00111000, 0b11010001, 0b01011101, 0b10111110, 0b11011100, 0b10100111], 
            [0b11011111, 0b01011100, 0b11010000, 0b00111011, 0b01111001, 0b11111110], 
            [0b01011110, 0b11100011, 0b11011000, 0b11100101, 0b11111001, 0b10110011], 
            [0b00011110, 0b11010101, 0b00001111, 0b11100111, 0b00101110, 0b01111111], 
            [0b01101011, 0b00001001, 0b01001111, 0b11111111, 0b10011011, 0b11011110], 
            [0b00101001, 0b11101000, 0b10101101, 0b00010101, 0b11010111, 0b11111111], 
            [0b10010001, 0b00101101, 0b10111010, 0b01011111, 0b10111100, 0b11100101], 
            [0b11110100, 0b00101110, 0b10110001, 0b11101010, 0b11101101, 0b11111101], 
            [0b00111000, 0b11111001, 0b00100110, 0b11110111, 0b11111100, 0b10101011]
        ];

        var keys =
            _container.Resolve<IKeySchedule>()
                .Expand(_key);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(keys)}Expected result:\n{Utils.BinaryToString(expectedResult)}");
        
        CollectionAssert.AreEqual(
            expectedResult, 
            keys);
    }
    
    #endregion
    
    #region RoundFunction

    [Test]
    public void DesRoundFunctionTest()
    {
        byte [] roundKey = 
        [
            0b11010111, 0b11101110, 0b00000101, 0b00101011, 0b11111111, 0b10011111
        ];
        
        byte [] block = 
        [
            0b01101101,0b11111111,0b10101010,0b01101110
        ];

        byte [] expectedResult = 
        [
            0b00001111,0b00101001,0b00100111,0b00010010
        ];
       
        _container.Resolve<IRoundFunction>()
            .TransformBlock(block, roundKey);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(block)}Expected result:\n{Utils.BinaryToString(expectedResult)}");

        CollectionAssert.AreEqual(
            expectedResult, 
            block);
    }
    
    #endregion
    
    #region DES BlockTransformation
    
    [Test]
    public void DesEncryptTest()
    {
        byte [] block = 
        [
            0b01101101,0b11111111,0b10101010,0b01101110,
            0b01101101,0b11111111,0b10101010,0b01101110
        ];
        
        byte [] expectedResult = 
        [
            0b01111110, 0b01111010, 0b11111100, 0b00001101,
            0b00011100, 0b11001100, 0b01010101, 0b01011101
        ];

        _container.Resolve<DES>()
            .EncryptBlock(block);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(block)}Expected result:\n{Utils.BinaryToString(expectedResult)}");

        CollectionAssert.AreEqual(
            expectedResult, 
            block);
    }
    
    [Test]
    public void DesDecryptTest()
    {
        byte [] block = 
        [
            0b01111110, 0b01111010, 0b11111100, 0b00001101,
            0b00011100, 0b11001100, 0b01010101, 0b01011101
        ];
        
        byte [] expectedResult = 
        [
            0b01101101,0b11111111,0b10101010,0b01101110,
            0b01101101,0b11111111,0b10101010,0b01101110
        ];
       
        var des = _container.Resolve<DES>();
        var method = typeof(DES).GetMethod(
                    "DecryptBlock", 
                    BindingFlags.NonPublic | BindingFlags.Instance);
        method?.Invoke(des, [block.AsMemory()]);
        
        Log.Information(
            $"Test Completed.\nResult:\n{Utils.BinaryToString(block)}Expected result:\n{Utils.BinaryToString(expectedResult)}");

        CollectionAssert.AreEqual(
            expectedResult, 
            block);
    }
    
    #endregion
}