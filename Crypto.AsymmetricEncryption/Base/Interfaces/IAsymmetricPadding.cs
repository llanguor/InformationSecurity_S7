using Crypto.Core.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

/// <summary>
/// Defines padding functionality for asymmetric encryption algorithms.
/// Inherits basic padding operations from <see cref="ICipherPadding"/>.
/// </summary>
public interface IAsymmetricPadding : 
    ICipherPadding
{
    /// <summary>
    /// Gets the size of a plaintext block that can be processed by the padding scheme.
    /// </summary>
    public int PlaintextBlockSize { get; }
    
    /// <summary>
    /// Gets the size of a ciphertext block produced by the padding scheme.
    /// </summary>
    public int CiphertextBlockSize { get; }
}