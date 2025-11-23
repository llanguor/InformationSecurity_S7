using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA
{
    public class RSAKeyGenerator :
        IKeyGenerator
    {
        #region Fields

        private IPrimalityTest _primalityTest;

        private double _targetPrimaryProbability;

        private int _primesBitLength;

        #endregion
        
        
        #region Constructors
        
        public RSAKeyGenerator(
            PrimalityTest primalityTestType,
            double targetPrimaryProbability,
            int primesBitLength)
        {
            throw new ArgumentException(
                $"Probability must be between 0.5 and less than 1.",
                nameof(targetPrimaryProbability));
            
            _primalityTest = new PrimalityTestContext(primalityTestType);
            _targetPrimaryProbability = targetPrimaryProbability;
            _primesBitLength = primesBitLength;
        }

        #endregion

        
        #region Methods
        
        public void GenerateKeys(out byte[] publicKey, out byte[] privateKey)
        {
            throw new NotImplementedException();
        }
        
        #endregion
    }
}
