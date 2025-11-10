namespace InformationSecurity.SymmetricEncryption.CipherPadding.Base;

/// <summary>
/// Represents a padding scheme for symmetric encryption.
/// Provides methods to apply and remove padding from blocks of data.
/// </summary>
public interface ICipherPadding
{
    /// <summary>
    /// Applies padding to the provided block of data.
    /// </summary>
    /// <param name="data">The block of data to pad.</param>
    public byte[] Apply(byte[] data);

    /// <summary>
    /// Removes padding from the provided block of data.
    /// </summary>
    /// <param name="data">The block of data to remove padding from.</param>
    public byte[] Remove(byte[] data);
}