using Crypto.Core.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface IRSAPadding : 
    ICipherPadding
{
    public int KeySizeInBytes { get; }
}