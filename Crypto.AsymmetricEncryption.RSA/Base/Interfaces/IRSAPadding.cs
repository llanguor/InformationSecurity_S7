using Crypto.Core.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

/// <summary>
/// Defines the contract for RSA padding schemes, including key size information.
/// </summary>
public interface IRSAPadding : 
    IAsymmetricPadding
{
    /// <summary>
    /// Gets the size of the RSA key in bytes for the padding scheme.
    /// </summary>
    public int KeySizeInBytes { get; }
}