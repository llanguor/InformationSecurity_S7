using System.Security.AccessControl;

namespace Crypto.SymmetricEncryption;

public sealed partial class RC4
{
    internal class RC4State
    {
        internal int I { get; set; } = 0;

        internal int J { get; set; } = 0;

        internal byte[] SBox { get; set; } = new byte[BoxSize];

        internal const int BoxSize = 256;
    }
}