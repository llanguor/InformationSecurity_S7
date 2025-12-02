using Crypto.Core;
using Crypto.Core.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

/// <summary>
/// Defines a generic asymmetric encryption algorithm with a specified key type.
/// Inherits common encryption operations from <see cref="IEncryptionAlgorithm"/>.
/// </summary>
public interface IAsymmetricEncryption<TKey> :
    IEncryptionAlgorithm
{
}