using System.Numerics;
using Crypto.Attacks.RSA.Core;
using Crypto.Tests.Infrastructure;
using DryIoc;

namespace Crypto.Tests.Attacks.RSA;

public class AttacksRSATest
{
    #region Initialization
    
    private Container? _container;
    
    [SetUp]
    public void Setup()
    {
        Logger.GetInstance();
        _container = new Container();
        _container.Register<MathService>(Reuse.Singleton);
    }
    
    [TearDown]
    public void TearDown()
    {
        _container?.Dispose();
    }
    
    #endregion
    
    
    #region Tests

    [Test]
    public void ComputeContinuedFractionTest()
    {
        ContinuedFractionAssert(23, 17, [1, 2, 1, 5]);
        ContinuedFractionAssert(77, 13, [5, 1, 12]);
        ContinuedFractionAssert(3, 1, [3]);
        ContinuedFractionAssert(415, 93, [4, 2, 6, 7]);
    }
    

    private void ContinuedFractionAssert(
        int numerator,
        int denominator,
        BigInteger[] expected)
    {
        Assert.That(
            _container.Resolve<MathService>()
                .ComputeContinuedFraction(
                    numerator,
                    denominator), 
            Is.EqualTo(expected));
    }
    
    [Test]
    public void ConvergentsTest()
    {
        ConvergentsAssert(77, 13, [
            new Tuple<BigInteger, BigInteger>(1,0),
            new Tuple<BigInteger, BigInteger>(5,1),
            new Tuple<BigInteger, BigInteger>(6,1),
            new Tuple<BigInteger, BigInteger>(77,13)
        ]);
    }
    
    private void ConvergentsAssert(
        BigInteger numerator,
        BigInteger denominator,
        Tuple<BigInteger, BigInteger>[] expected)
    {
        Assert.That(
            _container.Resolve<MathService>()
                .GetConvergentsFractions(
                    numerator,
                    denominator), 
            Is.EqualTo(expected));
    }
    
    [Test]
    public void DiscriminantTest()
    {
        DiscriminantAssert(1, 2, -3, []);
        DiscriminantAssert(1, -1, -56, []);
        DiscriminantAssert(2, -10, 12, [3, 2]);
    }
    
    private void DiscriminantAssert(
        BigInteger a,
        BigInteger b,
        BigInteger c,
        BigInteger[] expected)
    {
        Assert.That(
            _container.Resolve<MathService>()
                .SolveQuadraticForWienersAttack(a, b, c), 
            Is.EqualTo(expected));
    }

    
    #endregion
}