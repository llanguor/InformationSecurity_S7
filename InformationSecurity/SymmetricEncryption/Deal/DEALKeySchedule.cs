using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

namespace InformationSecurity.SymmetricEncryption.Deal;

public sealed class DEALKeySchedule 
    : IKeySchedule
{
    public byte[][] Expand(ReadOnlySpan<byte> key)
    {
        throw new NotImplementedException();
    }
}