namespace Crypto.SymmetricEncryption;

public sealed partial class RC4
{
    internal class PseudoRandomGenerationAlgorithm
    {
        #region Fields

        private int _i = 0;

        private int _j = 0;

        private const int BoxSize = 256;
        
        #endregion


        #region Methods

        public byte GetNextByte(byte[] sBox)
        {
            if (sBox == null)
                throw new ArgumentException("SBox cannot be null.", nameof(sBox)); 
            
            if (sBox.Length != BoxSize)
               throw new ArgumentException("SBox size must be 256 bytes.", nameof(sBox)); 
            
            _i = (_i + 1) % BoxSize;
            _j = (_j + 1) % BoxSize;
            (sBox[_i], sBox[_j]) = (sBox[_j], sBox[_i]);

            var resultIndex = (sBox[_i] + sBox[_j]) % BoxSize;

            return sBox[resultIndex];
        }

        #endregion
    }
}