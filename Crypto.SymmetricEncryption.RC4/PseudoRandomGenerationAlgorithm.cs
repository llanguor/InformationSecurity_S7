namespace Crypto.SymmetricEncryption.RC4;

public sealed partial class RC4
{
    internal class PseudoRandomGenerationAlgorithm
    {
        #region Fields

        private int _i = 0;

        private int _j = 0;

        #endregion


        #region Methods

        public byte GetNextByte(byte[] sBox)
        {
            _i = (_i + 1) % 256;
            _j = (_j + 1) % 256;
            (sBox[_i], sBox[_j]) = (sBox[_j], sBox[_i]);

            var resultIndex = (sBox[_i] + sBox[_j]) % 256;

            return sBox[resultIndex];
        }

        #endregion
    }
}