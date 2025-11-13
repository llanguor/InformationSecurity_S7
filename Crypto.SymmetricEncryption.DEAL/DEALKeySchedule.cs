using Crypto.SymmetricEncryption.FeistelNetwork.Base;

namespace Crypto.SymmetricEncryption;

public sealed class DEALKeySchedule 
    : IKeySchedule
{
    public byte[][] Expand(ReadOnlySpan<byte> key)
    {
        throw new NotImplementedException();
    }
}