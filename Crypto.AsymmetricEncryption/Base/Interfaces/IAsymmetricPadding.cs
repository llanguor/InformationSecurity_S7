using Crypto.Core.Base.Interfaces;

namespace Crypto.AsymmetricEncryption.Base.Interfaces;

public interface IAsymmetricPadding : 
    ICipherPadding
{
    public int PlaintextBlockSize { get; }
    
    public int CiphertextBlockSize { get; }
}