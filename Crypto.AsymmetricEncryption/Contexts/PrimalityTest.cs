namespace Crypto.AsymmetricEncryption.Contexts;

/// <summary>
/// Specifies the type of probabilistic primality test to use.
/// </summary>
public enum PrimalityTest
{
    /// <summary>Fermat primality test.</summary>
    Fermat,

    /// <summary>Miller-Rabin primality test.</summary>
    MillerRabin,

    /// <summary>Solovay-Strassen primality test.</summary>
    SolovayStrassen
}
