namespace Crypto.SymmetricEncryption.CipherPaddings;

/// <summary>
/// Defines the supported padding schemes for symmetric encryption.
/// Used to fill the last block to the required size if it is not complete.
/// </summary>
public enum CipherPaddings
{
    /// <summary>
    /// Pads the block with zeros.
    /// </summary>
    Zeros,

    /// <summary>
    /// Pads the block according to ANSI X.923.
    /// </summary>
    ANSIX923,

    /// <summary>
    /// Pads the block according to PKCS#7.
    /// </summary>
    PKCS7,

    /// <summary>
    /// Pads the block according to ISO 10126 (random padding bytes).
    /// </summary>
    ISO10126
}
