using Crypto.SymmetricEncryption.FeistelNetwork.Base;

namespace Crypto.SymmetricEncryption;

public sealed class DEAL(
    byte[] key, 
    CipherPaddings.CipherPaddings paddings, 
    CipherModes.CipherModes modes, 
    byte[]? initializationVector = null, 
    params object[] parameters)
    : SymmetricEncryption(8, key, paddings, modes, initializationVector, parameters)
{
    /// <summary>
    /// The Crypto.Core.DEAL key schedule used to generate round keys.
    /// </summary>
    private static readonly IKeySchedule KeySchedule =
        new DEALKeySchedule();
    
    /// <summary>
    /// The Crypto.Core.DEAL round function used in the Feistel network.
    /// </summary>
    private static readonly IRoundFunction RoundFunction =
        new DEALRoundFunctionAdapter();

    
    internal override void EncryptBlock(Memory<byte> data)
    {
        throw new NotImplementedException();
    }

    internal override void DecryptBlock(Memory<byte> data)
    {
        throw new NotImplementedException();
    }

    public override void SetKey(byte[] key)
    {
        throw new NotImplementedException();
    }
}