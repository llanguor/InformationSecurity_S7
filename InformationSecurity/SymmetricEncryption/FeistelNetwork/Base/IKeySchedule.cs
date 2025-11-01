namespace InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

/// <summary>
/// Interface that provides key expansion (generation) functionality.
/// Used to generate round keys from an original key.
/// </summary>
public interface IKeySchedule
{
    /// <summary>
    /// Generates a set of round keys from the specified master key.
    /// </summary>
    /// <param name="key">The master key as a byte array. For DES, it must be exactly 8 bytes long.</param>
    /// <returns>
    /// An array of round keys, where each element represents a single round key.
    /// </returns>
    byte[][] Expand(byte[] key);
}