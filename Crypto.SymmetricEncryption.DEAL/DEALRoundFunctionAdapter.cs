using Crypto.SymmetricEncryption.FeistelNetwork.Base;

namespace Crypto.SymmetricEncryption;

public sealed class DEALRoundFunctionAdapter 
    : IRoundFunction
{
    public void TransformBlock(Span<byte> block, ReadOnlySpan<byte> key)
    {
        throw new NotImplementedException();
    }
}