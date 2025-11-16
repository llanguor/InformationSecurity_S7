using Crypto.SymmetricEncryption.Base;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

public sealed class DEALKeySchedule 
    : KeyScheduleBase
{
    protected override byte[][] GenerateSchedule(ReadOnlySpan<byte> key)
    {
        throw new NotImplementedException();
    }
}