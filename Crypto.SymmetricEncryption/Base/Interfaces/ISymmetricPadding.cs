using Crypto.Core.Base.Interfaces;

namespace Crypto.SymmetricEncryption.Base.Interfaces;

public interface ISymmetricPadding : ICipherPadding
{
    public int BlockSize { get; }
}