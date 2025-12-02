namespace Crypto.AsymmetricEncryption.Base.Interfaces;

/// <summary>
/// Represents the possible outcomes of a primality test.
/// </summary>
public enum PrimalityResult
{
    /// <summary>
    /// Indicates that the tested number is prime.
    /// </summary>
    Prime = 1,
    
    /// <summary>
    /// Indicates that the tested number is composite (not prime).
    /// </summary>
    Composite = 0,
    
    /// <summary>
    /// Indicates that the primality of the tested number could not be determined with the given probability.
    /// </summary>
    Indeterminate = -1
}