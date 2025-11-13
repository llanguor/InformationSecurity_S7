using InformationSecurity.SymmetricEncryption.Des;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

namespace InformationSecurity.SymmetricEncryption.Deal;

public sealed class DEAL(
    byte[] key, 
    CipherPadding.Enum.CipherPadding padding, 
    CipherMode.Enum.CipherMode mode, 
    byte[]? initializationVector = null, 
    params object[] parameters)
    : SymmetricEncryption(8, key, padding, mode, initializationVector, parameters)
{
    /// <summary>
    /// The DEAL key schedule used to generate round keys.
    /// </summary>
    private static readonly IKeySchedule KeySchedule =
        new DEALKeySchedule();
    
    /// <summary>
    /// The DEAL round function used in the Feistel network.
    /// </summary>
    private static readonly IRoundFunction RoundFunction =
        new DEALAsRoundFunctionAdapter();

    
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