using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

public sealed class DESToDEALRoundFunctionAdapter(DES des)
    : IRoundFunction
{
    private readonly DES _des = des;
    
    public void TransformBlock(Span<byte> block, ReadOnlySpan<byte> key)
    {
        _des.Key = key.ToArray();
        _des.EncryptBlock(block.ToArray());
    }
}