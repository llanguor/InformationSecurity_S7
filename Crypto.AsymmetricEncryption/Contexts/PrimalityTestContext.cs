using System.Numerics;
using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.PrimalityTests;

namespace Crypto.AsymmetricEncryption.Contexts;

public sealed class PrimalityTestContext  :
    IPrimalityTest
{
    #region Fields

    private PrimalityTestBase _primalityTest = null!;
    
    private PrimalityTest _primalityTestType;

    #endregion
    
    
    #region Properties

    public PrimalityTest PrimalityTestType
    {
        get => _primalityTestType;
        set
        {
            _primalityTestType = value; 
            _primalityTest = value switch
            {
                PrimalityTest.Fermat =>
                    new FermatPrimalityTest(),
                
                PrimalityTest.MillerRabin =>
                    new MillerRabinPrimalityTest(),
                
                PrimalityTest.SolovayStrassen =>
                    new SolovayStrassenPrimalityTest(),
                
                _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
            };
        }
    }
    
    #endregion
    
    
    #region Constructors

    public PrimalityTestContext(
        PrimalityTest primalityTestType)
    {
        PrimalityTestType = primalityTestType;
    }

    #endregion
    
    
    #region Methods

    public PrimalityResult IsPrimary(BigInteger value, double targetProbability)
    {
        return _primalityTest.IsPrimary(value, targetProbability);
    }
    
    #endregion
}