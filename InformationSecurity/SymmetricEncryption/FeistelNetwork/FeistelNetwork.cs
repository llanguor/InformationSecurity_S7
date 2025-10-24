
using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

namespace InformationSecurity.SymmetricEncryption.FeistelNetwork;

public sealed class FeistelNetwork (
    IKeyExpansion keyExpansion, 
    IRoundFunction roundFunction,
    byte[] key,
    int roundsCount)
    : IEncryption
{
    #region Fields
    
    private readonly IKeyExpansion _keyExpansion = keyExpansion;
    
    private readonly IRoundFunction _roundFunction = roundFunction;

    private byte[][] _roundKeys = keyExpansion.Expand(key);

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
        _roundKeys = _keyExpansion.Expand(key);
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