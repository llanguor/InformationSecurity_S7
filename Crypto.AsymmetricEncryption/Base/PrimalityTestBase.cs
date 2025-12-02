using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base;

/// <summary>
/// Provides a base implementation for primality tests with probabilistic accuracy.
/// Uses a random value generator and a cryptographic math service for computations.
/// </summary>
/// <param name="oneIterationErrorProbability">The probability of error for a single iteration of the test.</param>
public abstract class PrimalityTestBase(
    double oneIterationErrorProbability) :
    IPrimalityTest
{
    #region Properties
    
    /// <summary>
    /// The probability that a single iteration of the primality test produces an incorrect result.
    /// </summary>
    protected double OneIterationErrorProbability { get; } =
        oneIterationErrorProbability;
    
    /// <summary>
    /// Provides cryptographic mathematical operations, such as modular exponentiation and GCD calculations.
    /// </summary>
    protected static ICryptoMathService CryptoMathService { get; } = 
        new CryptoMathService();
    
    /// <summary>
    /// Random number generator used to produce values for the primality test iterations.
    /// </summary>
    public Random Randomizer { get; set; } =
        new Random(Environment.TickCount);
    
    #endregion
    
    
    #region Methods
    
    /// <summary>
    /// Determines whether a given integer is prime using a probabilistic test.
    /// </summary>
    /// <param name="value">The integer to test for primality.</param>
    /// <param name="targetProbability">The desired confidence probability (between 0.5 and less than 1).</param>
    /// <returns>A <see cref="PrimalityResult"/> indicating whether the number is prime, composite, or indeterminate.</returns>
    public PrimalityResult IsPrimary(
        BigInteger value, 
        double targetProbability)
    {
        if (targetProbability < 0.5 ||
            targetProbability >= 1)
            throw new ArgumentException(
                $"Probability must be between 0.5 and less than 1.",
                nameof(targetProbability));
        
        if (value < 2)
            return PrimalityResult.Indeterminate;
        
        if (value  == 2 || value == 3)
            return PrimalityResult.Prime;

        if ((value & 1) == 0 || value % 3 == 0)
            return PrimalityResult.Composite;
        
        for (var i = 0; 
             i < GetIterationsCount(
                 1 - targetProbability, 
                 OneIterationErrorProbability); 
             i++)
        {
            var random  
                = GenerateRandomNaturalValue(2, value);
            
            if (!IsCoprime(value, random) ||
                !ValidateCondition(value, random))
            {
                return PrimalityResult.Composite;
            }
        }
        
        return PrimalityResult.Prime;
    }
    
    /// <summary>
    /// Calculates the number of iterations required to achieve the target error probability.
    /// </summary>
    /// <param name="targetErrorProbability">The acceptable error probability for the test.</param>
    /// <param name="oneIterationErrorProbability">The error probability of a single iteration.</param>
    /// <returns>The number of iterations to perform.</returns>
    private int GetIterationsCount(
        double targetErrorProbability, 
        double oneIterationErrorProbability)
    {
        return (int) Math.Ceiling(
            Math.Log(targetErrorProbability) /
            Math.Log(oneIterationErrorProbability));
    }
    
    /// <summary>
    /// Generates a random natural number within the specified range.
    /// </summary>
    /// <param name="minValue">The inclusive minimum value.</param>
    /// <param name="maxValue">The exclusive maximum value.</param>
    /// <returns>A random long integer between minValue (inclusive) and maxValue (exclusive).</returns>
    protected virtual long GenerateRandomNaturalValue(
        BigInteger minValue, 
        BigInteger maxValue)
    {
        if (minValue >= maxValue)
            throw new ArgumentException("minValue must be < maxValue");

        var min = 
            minValue < long.MinValue ? 
            long.MinValue : 
            (long)minValue;
        
        var max = 
            maxValue > long.MaxValue ? 
                long.MaxValue : 
                (long)maxValue;

        return Randomizer.NextInt64(min, max);
    }
    
    /// <summary>
    /// Determines whether two integers are coprime (i.e., their greatest common divisor is 1).
    /// </summary>
    /// <param name="p">The first integer.</param>
    /// <param name="a">The second integer.</param>
    /// <returns>True if the numbers are coprime; otherwise, false.</returns>
    private bool IsCoprime(
        BigInteger p, 
        BigInteger a)
    {
        return CryptoMathService
            .CalculateGcdEuclidean(p, a) == 1;
    }
    
    /// <summary>
    /// Validates the primality test condition for a single iteration using the given base.
    /// Must be implemented by derived classes for specific primality test algorithms.
    /// </summary>
    /// <param name="p">The integer to test for primality.</param>
    /// <param name="a">The randomly selected base for this iteration.</param>
    /// <returns>True if the condition passes; otherwise, false.</returns>
    protected abstract bool ValidateCondition(
        BigInteger p,
        BigInteger a);
    
    #endregion
}