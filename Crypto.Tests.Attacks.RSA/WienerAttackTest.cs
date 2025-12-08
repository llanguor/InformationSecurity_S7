using System.Numerics;
using Crypto.AsymmetricEncryption;
using Crypto.AsymmetricEncryption.Contexts;
using Crypto.Attack.RSA;
using Crypto.Attacks.RSA.Core;
using Crypto.Tests.Infrastructure;
using DryIoc;
using Serilog;

namespace Crypto.Tests.Attacks.RSA;

public class WienerAttackTest
{
    #region Initialization
    
    private Container? _container;
    
    private const Crypto.AsymmetricEncryption.RSA.RSAKeySize KeySize = 
        Crypto.AsymmetricEncryption.RSA.RSAKeySize.Bits1024;
    
    private const double TargetPrimaryProbability = 0.999;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.Register<WienersAttack>(Reuse.Singleton);
        _container.Register<CryptoMathService>(Reuse.Singleton);
        _container.RegisterInstance(
            new Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator(
                PrimalityTest.MillerRabin, 
                KeySize, 
                TargetPrimaryProbability)
                {
                    ESize = 16
                });
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Tests

    [Test]
    public void WienerAttackPerformTest()
    {
        var math = _container.Resolve<CryptoMathService>();
        var keyGenerator = _container.Resolve<Crypto.AsymmetricEncryption.RSA.RSAKeyGenerator>();
        var wiener = _container.Resolve<WienersAttack>();

        keyGenerator.GenerateKeys(
            out var privateKey, 
            out var publicKey);
        
        while (privateKey.Exponent >= 
               math.Sqrt(privateKey.Modulus, 4) / 3)
        {
            keyGenerator.GenerateKeys(
                out privateKey, 
                out publicKey);
        }

        try
        {
            var dValue =
                wiener.Perform(publicKey);

            Log.Information($"Real rsa d-value:\t\t{privateKey.Exponent}");
            Log.Information($"Wiener's AttackResult:\t{dValue}");
 
            Assert.That(
                dValue,
                Is.EqualTo(privateKey.Exponent));
        }
        catch (InvalidOperationException)
        {
            Log.Information("d was not found. Wiener attack failed for this key.");
            Assert.False(true, "Wiener attack did not find d");
        }
    }
    
    #endregion
}