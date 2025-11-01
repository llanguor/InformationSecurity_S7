
using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

namespace InformationSecurity.SymmetricEncryption.FeistelNetwork;

public sealed class FeistelNetwork (
    IKeySchedule keySchedule, 
    IRoundFunction roundFunction,
    byte[] key,
    int roundsCount)
    : IEncryption
{
    #region Fields
    
    private readonly IKeySchedule _keySchedule = keySchedule;
    
    private readonly IRoundFunction _roundFunction = roundFunction;

    private byte[][] _roundKeys = keySchedule.Expand(key);

    private int _roundsCount = roundsCount;
    
    #endregion
    
    
    #region ...?Fields

    private static readonly int[] P1 = 
    [
    
    ]; 
    
    #endregion
    
    
    #region Methods

    public void SetKey(byte[] key)
    {
        _roundKeys = _keySchedule.Expand(key);
    }

    public byte[] Encrypt(byte[] data)
    {
        throw new NotImplementedException();
    }

    public byte[] Decrypt(byte[] data)
    {
        throw new NotImplementedException();
    }
    
    #endregion
}