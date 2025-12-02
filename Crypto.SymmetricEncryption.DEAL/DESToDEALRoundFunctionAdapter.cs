using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

public sealed partial class DEAL
{
    /// <summary>
    /// Adapter enabling DES to be used as the round function for DEAL.
    /// </summary>
    /// <param name="des">DES instance used for round transformations.</param>
    internal sealed class DESToDEALRoundFunctionAdapter(DES des)
        : IRoundFunction
    {
        /// <exception cref="ArgumentNullException"></exception>
        /// <inheritdoc />
        public void TransformBlock(Memory<byte> block, byte[] key)
        {
            des.Key = key;
            des.EncryptBlock(block);
        }
    }
}