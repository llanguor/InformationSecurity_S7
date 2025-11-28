using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption.Base;

public abstract class RSAPaddingBase(
    RSA.RSAKeySize keySize) :
    IRSAPadding
{
    public int KeySizeInBytes { get; } = (int)keySize / 8;

    public abstract int PlaintextBlockSize { get; }
    
    public abstract int CiphertextBlockSize { get; }
    

    public abstract byte[] Apply(Span<byte> data);

    public abstract byte[] Remove(Span<byte> data);
}