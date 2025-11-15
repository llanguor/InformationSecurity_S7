namespace Crypto.SymmetricEncryption.Base.Interfaces;

/// <summary>
/// Provides key expansion (generation) functionality for a Feistel network.
/// Used to generate round keys from a master key.
/// </summary>
public interface IKeySchedule
{
    /// <summary>
    /// Expands the specified master key into a set of round keys.
    /// </summary>
    /// <param name="key">
    ///     The master key as a read-only span of bytes. 
    ///     For Crypto.Core.DES, it must be exactly 8 bytes long.
    /// </param>
    /// <returns>
    /// An array of round keys, where each element represents a single round key.
    /// </returns>
    byte[][] Expand(ReadOnlySpan<byte> key);
}