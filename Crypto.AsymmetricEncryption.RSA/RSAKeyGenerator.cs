using System.Numerics;
using System.Security.Cryptography;
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

        private readonly int _primesBitLength;
        
        private readonly int _keySizeInBits;

        #endregion
        
        
        #region Constructors
        
        public RSAKeyGenerator(
            PrimalityTest primalityTestType,
            double targetPrimaryProbability,
            int primesBitLength,
            int keySizeInBits)
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
            _primesBitLength = primesBitLength;
            _keySizeInBits = keySizeInBits;
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

        private void GeneratePrime(
            out BigInteger result,
            byte prefixInBytes, 
            int prefixLength)
        {
            var bytes = new byte[_primesBitLength];
            RandomNumberGenerator.Fill(bytes.AsSpan(0, bytes.Length - 1));
           
            bytes[0] |= 0b00000001;
            bytes[^2] = (byte)(
                bytes[^2] & 
                (0xFF >> prefixLength) | 
                (0xFF << (8-prefixLength) & prefixInBytes));
            
            result = new BigInteger(
                bytes.AsSpan(), 
                isUnsigned: false,
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
                    return;
            }
        }

        private void GenerateE(
            out BigInteger result,
            ref readonly BigInteger n)
        {
            var bytes = new byte[_keySizeInBits];
            
            while (true)
            {
                RandomNumberGenerator.Fill(bytes);
                result = new BigInteger(
                    bytes,
                    isUnsigned: false,
                    isBigEndian: false);
                
                var isCoprime = _cryptoMathService
                    .CalculateGcdEuclidean(result, n) == 1;
                var isMin = true; //todo: implement minimal count of 1
                
                if (isCoprime &&
                    isMin)
                    return;
            }
        }

        private void CalculateD(
            out BigInteger result,
            ref readonly BigInteger e,
            ref readonly BigInteger eulerN)
        {
            _cryptoMathService.CalculateGcdEuclidean(
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
