using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA(
    PrimalityTest primalityTestType,
    double targetPrimaryProbability,
    int primesBitLength) : 
    IAsymmetricEncryption
{
    #region Fields
    
    private RSAKeyGenerator _keyGenerator =
            new RSAKeyGenerator(
                primalityTestType,
                targetPrimaryProbability, 
                primesBitLength);
    
    #endregion
    
    
    #region Methods
    
    public Memory<byte> Encrypt(Memory<byte> data)
    {
        throw new NotImplementedException();
    }

    public Memory<byte> Decrypt(Memory<byte> data)
    {
        throw new NotImplementedException();
    }
    
    #endregion
}