using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base;

public abstract class CipherPaddingBase (
    int blockSize)
    : ICipherPadding
{
    protected int BlockSize { get; } = blockSize;
    
    public abstract byte[] Apply(Span<byte> data);

    public abstract byte[] Remove(Span<byte> data);
}