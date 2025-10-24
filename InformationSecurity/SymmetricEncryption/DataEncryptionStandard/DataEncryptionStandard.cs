using InformationSecurity.SymmetricEncryption.Base;
using InformationSecurity.SymmetricEncryption.FeistelNetwork;
using InformationSecurity.SymmetricEncryption.FeistelNetwork.Base;

namespace InformationSecurity.SymmetricEncryption.DataEncryptionStandard;

public sealed class DataEncryptionStandard(byte[] key)
    : IEncryption
{
    #region Fields
    
    private static readonly IKeyExpansion KeyExpansion =
        new DesKeyExpansion();
    
    private static readonly IRoundFunction RoundFunction =
        new DesRoundFunction();
    
    private readonly FeistelNetwork.FeistelNetwork _feistelNetwork = 
        new (KeyExpansion, RoundFunction, key, 16);
    
    #endregion
    
    
    #region Methods
    
    public void SetKey(byte[] key)
    {
        _feistelNetwork.SetKey(key);
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