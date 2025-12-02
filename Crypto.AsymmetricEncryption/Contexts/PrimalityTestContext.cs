using System.Numerics;
using Crypto.AsymmetricEncryption.Base;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.PrimalityTests;

namespace Crypto.AsymmetricEncryption.Contexts;

/// <summary>
/// Provides a context for performing primality tests using a selected algorithm.
/// Allows switching between Fermat, Miller-Rabin, and Solovay-Strassen tests.
/// </summary>
public sealed class PrimalityTestContext  :
    IPrimalityTest
{
    #region Fields

    private PrimalityTestBase _primalityTest = null!;
    
    private PrimalityTest _primalityTestType;

    #endregion
    
    
    #region Properties
    
    /// <summary>
    /// Gets or sets the current primality test algorithm. Setting this property switches the underlying test implementation.
    /// </summary>
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

    /// <summary>
    /// Initializes a new instance of <see cref="PrimalityTestContext"/> with the specified primality test type.
    /// </summary>
    /// <param name="primalityTestType">The type of primality test to use.</param>
    public PrimalityTestContext(
        PrimalityTest primalityTestType)
    {
        PrimalityTestType = primalityTestType;
    }

    #endregion
    
    
    #region Methods

    /// <summary>
    /// Determines whether the specified value is prime using the selected primality test algorithm.
    /// </summary>
    /// <param name="value">The number to test for primality.</param>
    /// <param name="targetProbability">The desired confidence level for the result (between 0.5 and less than 1).</param>
    /// <returns>A <see cref="PrimalityResult"/> indicating whether the number is prime, composite, or indeterminate.</returns>
    public PrimalityResult IsPrimary(BigInteger value, double targetProbability)
    {
        return _primalityTest.IsPrimary(value, targetProbability);
    }
    
    #endregion
}