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
    /// <param name="blockSize">The size of the cipher block in bytes.</param>
    public void ApplyPadding(Span<byte> data, int blockSize);

    /// <summary>
    /// Removes padding from the provided block of data.
    /// </summary>
    /// <param name="data">The block of data to remove padding from.</param>
    /// <param name="blockSize">The size of the cipher block in bytes.</param>
    public void RemovePadding(Span<byte> data, int blockSize);
}