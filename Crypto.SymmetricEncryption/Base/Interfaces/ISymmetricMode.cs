using Crypto.Core.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base.Interfaces;

/// <summary>
/// Defines the contract for symmetric block cipher modes of operation.
/// Implementations provide encryption and decryption of data according
/// to a specific mode (e.g., ECB, CBC, CFB, OFB, CTR).
/// </summary>
public interface ISymmetricMode : ICipherMode
{
}