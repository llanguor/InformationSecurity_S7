namespace Crypto.SymmetricEncryption.RC4;

public sealed partial class RC4
{
    internal class KeySchedule
    {
        #region Fields

        private readonly byte[] _sBox = new byte[BoxSize];

        private const int BoxSize = 256;

        #endregion


        #region Properties

        public byte[] SBox => _sBox;

        #endregion


        #region Methods

        public byte[] Expand(byte[] key)
        {
            var kBox = new byte[BoxSize];

            for (var i = 0; i < BoxSize; ++i)
            {
                _sBox[i] = (byte)i;
            }

            for (var i = 0; i < BoxSize; ++i)
            {
                kBox[i] = key[i % key.Length];
            }

            var j = 0;
            for (var i = 0; i < BoxSize; ++i)
            {
                j = (j + _sBox[i] + kBox[i]) % BoxSize;
                (_sBox[i], _sBox[j]) = (_sBox[j], _sBox[i]);
            }

            return _sBox;
        }

        #endregion
    }
}