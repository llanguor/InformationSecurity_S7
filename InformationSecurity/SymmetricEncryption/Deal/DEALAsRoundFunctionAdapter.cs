using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

namespace InformationSecurity.SymmetricEncryption.Deal;

public sealed class DEALAsRoundFunctionAdapter 
    : IRoundFunction
{
    public void TransformBlock(Span<byte> block, ReadOnlySpan<byte> key)
    {
        throw new NotImplementedException();
    }
}