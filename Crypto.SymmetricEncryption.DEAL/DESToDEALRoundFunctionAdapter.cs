using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

public sealed partial class DEAL
{
    public sealed class DESToDEALRoundFunctionAdapter(DES des)
        : IRoundFunction
    {
        public void TransformBlock(Memory<byte> block, byte[] key)
        {
            des.Key = key;
            des.EncryptBlock(block);
        }
    }
}