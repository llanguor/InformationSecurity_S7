using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

public sealed class DESToDEALRoundFunctionAdapter(DES des)
    : IRoundFunction
{
    private readonly DES _des = des;
    
    public byte[] TransformBlock(byte[] block, byte[] key)
    {
        _des.SetKey(key);
        _des.EncryptBlock(block);
        return block;
    }
}