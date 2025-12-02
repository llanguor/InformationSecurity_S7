using System.IO.Enumeration;
using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA
{
    /// <summary>
    /// Generates RSA public and private keys using configurable key size, primality test, and target prime probability.
    /// </summary>
    internal class RSAKeyGenerator :
        IKeyGenerator<RSAKey>
    {
        #region Fields

        private readonly IPrimalityTest _primalityTest;

        private readonly double _targetPrimaryProbability;
        
        private readonly int _keySizeInBytes;

        internal const int E = 65537;

        #endregion
        
        
        #region Constructors
        
        /// <summary>
        /// Initializes a new instance of the <see cref="RSAKeyGenerator"/> class.
        /// </summary>
        /// <param name="primalityTestType">Type of primality test to use for prime generation.</param>
        /// <param name="keySize">Size of the RSA key.</param>
        /// <param name="targetPrimaryProbability">Target probability for generated numbers to be prime (between 0.5 and 1).</param>
        /// <exception cref="ArgumentException">Thrown if targetPrimaryProbability is not in the valid range.</exception>
        public RSAKeyGenerator(
            PrimalityTest primalityTestType,
            RSAKeySize keySize,
            double targetPrimaryProbability)
        {
            if (targetPrimaryProbability < 0.5 ||
                targetPrimaryProbability >= 1.0)
            {
                throw new ArgumentException(
                    $"Probability must be between 0.5 and less than 1.",
                    nameof(targetPrimaryProbability));
            }
            
            _primalityTest = new PrimalityTestContext(primalityTestType);
            _targetPrimaryProbability = targetPrimaryProbability;
            _keySizeInBytes = (int)keySize/8;
        }

        #endregion

        
        #region Methods
        
        /// <inheritdoc/>
        public void GenerateKeys(out RSAKey publicKey, out RSAKey privateKey)
        {
            while (true)
            {
                GeneratePrime(out var p, 0b10, 2);
                GeneratePrime(out var q, 0b11, 2);
            
                var n = p * q;
                var eulerN = (p - 1) * (q - 1);

                if (CryptoMathService.CalculateGcdEuclidean(eulerN, E) != 1)
                {
                    continue;
                }
                
                CalculateD(out var d, ref eulerN);

                if (d <= FourthRoot(n) / 3)
                {
                    continue;
                }
                
                publicKey = new RSAKey(E, n);
                privateKey = new RSAKey(d, n);
                return;
            }
        }
        
        /// <summary>
        /// Generates a prime number with a specific byte prefix and length.
        /// </summary>
        /// <param name="result">Output parameter for the generated prime number.</param>
        /// <param name="prefixInBytes">The byte prefix for the generated number.</param>
        /// <param name="prefixLength">Number of bits used for the prefix.</param>
        internal void GeneratePrime(
            out BigInteger result,
            byte prefixInBytes, 
            int prefixLength)
        {
            var bytes = new byte[_keySizeInBytes/2]; //because N = p * q: |a^x| = |b^(x/2)| + |c^(x/2)|
            System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
           
            bytes[0] |= 0b00000001;
            bytes[^1] = (byte)(
                bytes[^1] & 
                (0xFF >> prefixLength) | 
                (0xFF << (8-prefixLength) & prefixInBytes));
            
            result = new BigInteger(
                bytes.AsSpan(), 
                isUnsigned: true,
                isBigEndian: false);
            
            
            int[] increments = 
            [
                2, 2, 4
            ];
            
            var sign = 
                bytes[^1] == 0xFF ? -1 : 1;

            for (var i = 0; ; ++i)
            {
                result += sign * increments[i % 3];
                var isPrime = 
                    _primalityTest.IsPrimary(result, _targetPrimaryProbability);

                if (isPrime == PrimalityResult.Prime)
                {
                    return;
                }
            }
        }

        /// <summary>
        /// Calculates the private exponent 'd' for RSA using the extended Euclidean algorithm.
        /// </summary>
        /// <param name="result">Output parameter for the private exponent.</param>
        /// <param name="eulerN">Euler's totient of the modulus.</param>
        internal void CalculateD(
            out BigInteger result,
            ref readonly BigInteger eulerN)
        {
            CryptoMathService.CalculateGcdEuclidean(
                E, 
                eulerN, 
                out _,
                out result,
                out _);

            if (result < 0)
                result += eulerN;
        }
        
        /// <summary>
        /// Computes the integer fourth root of a given BigInteger using the Newton–Raphson iteration.
        /// The iterative formula used is:
        /// xₖ₊₁ = (3*xₖ + n / xₖ³) / 4
        /// </summary>
        /// <param name="n">The BigInteger to compute the fourth root of. Must be non-negative.</param>
        /// <returns>The largest integer x such that x⁴ ≤ n.</returns>
        /// <exception cref="ArithmeticException">Thrown if <paramref name="n"/> is negative.</exception>
        internal BigInteger FourthRoot(BigInteger n)
        {
            if (n < 0)
                throw new ArithmeticException(
                    "The algorithm does not assume finding the root of negative values");

            if (n == 0)
                return 0;

            if (n < 16)
                return 1;
            
            var x = n >> (int)(n.GetBitLength() / 4); 
            BigInteger result;

            do
            {
                result = x;
                x = (3 * x + n / (x * x * x)) >> 2; // x_k+1 = (3*x + n/x^3)/4
            } 
            while (x < result);

            return result;
        }

        
        #endregion
    }
}
