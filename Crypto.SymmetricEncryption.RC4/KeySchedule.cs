namespace Crypto.SymmetricEncryption;

public sealed partial class RC4
{
    internal class KeySchedule(RC4State state)
    {
        public byte[] Expand(byte[] key)
        {
            if (key == null)
                throw new ArgumentException("Key cannot be null.", nameof(key));
            
            if (key.Length < 2)
                throw new ArgumentException("SBox size must be more than 1.", nameof(key)); 

            
            var kBox = new byte[RC4State.BoxSize];

            for (var i = 0; i < RC4State.BoxSize; ++i)
            {
                state.SBox[i] = (byte)i;
            }

            for (var i = 0; i < RC4State.BoxSize; ++i)
            {
                kBox[i] = key[i % key.Length];
            }

            var j = 0;
            for (var i = 0; i < RC4State.BoxSize; ++i)
            {
                j = (j + state.SBox[i] + kBox[i]) % RC4State.BoxSize;
                (state.SBox[i], state.SBox[j]) = (state.SBox[j], state.SBox[i]);
            }

            return state.SBox;
        }
    }
}