using Crypto.Core;
using Crypto.SymmetricEncryption.Base.Interfaces;

namespace Crypto.SymmetricEncryption;

public sealed class DEAL(
    byte[] key,
    CipherPadding padding,
    CipherMode mode,
    byte[]? initializationVector = null,
    params object[] parameters)
    : SymmetricEncryption(8, key, padding, mode, initializationVector, parameters)
{
    #region Fields

    /// <summary>
    /// The Crypto.Core.DEAL key schedule used to generate round keys.
    /// </summary>
    private static readonly IKeySchedule KeySchedule =
        new DEALKeySchedule();

    /// <summary>
    /// The Crypto.Core.DEAL round function used in the Feistel network.
    /// </summary>
    private readonly IRoundFunction RoundFunction = 
        new DESToDEALRoundFunctionAdapter(
            new DES(
                key,
                padding,
                mode,
                initializationVector,
                parameters));

    #endregion
    
    
    #region Methods
    
    internal override void EncryptBlock(Memory<byte> data)
    {
        throw new NotImplementedException();
    }

    internal override void DecryptBlock(Memory<byte> data)
    {
        throw new NotImplementedException();
    }
    
    #endregion
}