using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base;

public abstract class PrimalityTestBase(
    double oneIterationErrorProbability) :
    IPrimalityTest
{
    #region Properties
    
    protected double OneIterationErrorProbability { get; } =
        oneIterationErrorProbability;
    
    protected static ICryptoMathService CryptoMathService { get; } = 
        new CryptoMathService();
    
    protected static Random Randomizer { get;  } = 
        new();
    
    #endregion
    
    
    #region Methods
    
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
    
    protected virtual int GetIterationsCount(
        double targetErrorProbability, 
        double oneIterationErrorProbability)
    {
        return (int) Math.Ceiling(
            Math.Log(targetErrorProbability) /
            Math.Log(oneIterationErrorProbability));
    }
    
    protected virtual long GenerateRandomNaturalValue(
        BigInteger minValue, 
        BigInteger maxValue)
    {
        return Randomizer.NextInt64(
                (long)minValue, 
                (long)maxValue);
    }
    
    protected virtual bool IsCoprime(
        BigInteger p, 
        BigInteger a)
    {
        return CryptoMathService
            .CalculateGcdEuclidean(p, a) == 1;
    }
    
    protected abstract bool ValidateCondition(
        BigInteger p,
        BigInteger a);
    
    #endregion
}