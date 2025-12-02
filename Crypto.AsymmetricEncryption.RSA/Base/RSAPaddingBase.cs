using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption.Base;

/// <summary>
/// Base class for RSA padding schemes, providing key size information and abstract methods
/// for applying and removing padding.
/// </summary>
public abstract class RSAPaddingBase :
    IRSAPadding
{
    /// <summary>
    /// Base class for RSA padding schemes, providing key size information and abstract methods
    /// for applying and removing padding.
    /// </summary>
    /// <param name="keySize">The RSA key size used to determine block sizes.</param>
    protected RSAPaddingBase(RSA.RSAKeySize keySize)
    {
        if (keySize <= 0)
            throw new ArgumentException("KeySize must be greater than zero.");
        
        KeySizeInBytes = (int)keySize / 8;
    }

    /// <summary>
    /// Gets the size of the RSA key in bytes.
    /// </summary>
    public int KeySizeInBytes { get; }

    ///<inheritdoc/>
    public abstract int PlaintextBlockSize { get; }
    
    ///<inheritdoc/>
    public abstract int CiphertextBlockSize { get; }
    
    ///<inheritdoc/>
    public abstract byte[] Apply(Span<byte> data);
    
    ///<inheritdoc/>
    public abstract byte[] Remove(Span<byte> data);
}