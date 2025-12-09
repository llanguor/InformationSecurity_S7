namespace Crypto.SymmetricEncryption;

public sealed partial class RC4
{
    internal class PseudoRandomGenerationAlgorithm(RC4State state)
    {
        public byte GetNextByte(byte[] sBox)
        {
            if (sBox == null)
                throw new ArgumentException("SBox cannot be null.", nameof(sBox)); 
            
            if (sBox.Length != RC4State.BoxSize)
               throw new ArgumentException("SBox size must be 256 bytes.", nameof(sBox)); 
            
            state.I = (state.I + 1) % RC4State.BoxSize;
            state.J = (state.J + state.SBox[state.I]) % RC4State.BoxSize;
            (sBox[state.I], sBox[state.J]) = (sBox[state.J], sBox[state.I]);

            var resultIndex = (sBox[state.I] + sBox[state.J]) % RC4State.BoxSize;

            return sBox[resultIndex];
        }
    }
}