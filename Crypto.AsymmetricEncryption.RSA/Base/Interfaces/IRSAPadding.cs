using Crypto.Core.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface IRSAPadding : 
    IAsymmetricPadding
{
    public int KeySizeInBytes { get; }
}