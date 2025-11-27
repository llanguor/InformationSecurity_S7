using System.IO.Enumeration;
using System.Numerics;
using Crypto.AsymmetricEncryption.Base.Interfaces;
using Crypto.AsymmetricEncryption.Contexts;

namespace Crypto.AsymmetricEncryption;

public sealed partial class RSA
{
    internal class RSAKeyGenerator :
        IKeyGenerator<RSAKey>
    {
        #region Fields

        private readonly IPrimalityTest _primalityTest;

        private readonly double _targetPrimaryProbability;
        
        private readonly int _keySizeInBytes;

        private const int _eSize = 3;

        #endregion
        
        
        #region Constructors
        
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
        
        public void GenerateKeys(out RSAKey publicKey, out RSAKey privateKey)
        {
            GeneratePrime(out var p, 0b10, 2);
            GeneratePrime(out var q, 0b11, 2);
            
            var n = p * q;
            var eulerN = (p - 1) * (q - 1);
            var minD = FourthRoot(n) / 3;
            
            while (true)
            {
                GenerateE(out var e, ref eulerN);
                CalculateD(out var d, ref e, ref eulerN);

                if (d > minD)
                {
                    publicKey = new RSAKey(e, n);
                    privateKey = new RSAKey(d, n);
                    return;
                }
            }
        }
        
        internal void GeneratePrime(
            out BigInteger result,
            byte prefixInBytes, 
            int prefixLength)
        {
            var bytes = new byte[_keySizeInBytes/2]; //because N = p * q: a^x = b^(x/2) * c^(x/2)
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
            
            // TODO: Improve performance
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

        internal void GenerateE(
            out BigInteger result,
            ref readonly BigInteger n)
        {
            var bytes = new byte[_eSize];

            while (true)
            {
                System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
                result = new BigInteger(
                    bytes,
                    isUnsigned: true,
                    isBigEndian: false);
                
                var isCoprime = CryptoMathService
                    .CalculateGcdEuclidean(result, n) == 1;
                var isMin = true; //todo: implement minimal count of 1
                
                if (isCoprime &&
                    isMin)
                    return;
            }
        }

        internal void CalculateD(
            out BigInteger result,
            ref readonly BigInteger e,
            ref readonly BigInteger eulerN)
        {
            CryptoMathService.CalculateGcdEuclidean(
                e, 
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
