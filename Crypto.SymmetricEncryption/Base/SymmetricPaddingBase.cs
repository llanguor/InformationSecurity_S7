using Crypto.Core.Base.Interfaces;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base;

public abstract class SymmetricPaddingBase (
    int blockSize)
    : ISymmetricPadding
{
    public int BlockSize { get; } = blockSize;
    
    public abstract byte[] Apply(Span<byte> data);

    public abstract byte[] Remove(Span<byte> data);
}