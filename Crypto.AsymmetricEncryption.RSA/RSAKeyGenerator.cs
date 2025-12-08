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
        
        private readonly CryptoMathService _cryptoMathService
            = new();

        private readonly IPrimalityTest _primalityTest;

        private readonly double _targetPrimaryProbability;
        
        private readonly int _keySizeInBytes;
        
        internal int ESize = 3;

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
            GeneratePrime(out var p, 0b10, 2);
            GeneratePrime(out var q, 0b11, 2);
            
            var n = p * q;
            var eulerN = (p - 1) * (q - 1);
            var minD = _cryptoMathService.Sqrt(n, 4) / 3;
            
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
        
        internal void GenerateE(
            out BigInteger result,
            ref readonly BigInteger n)
        {
            var bytes = new byte[ESize];
            
            while (true)
            {
                System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
                
                //Minimize the number of ones in the bit representation
                for (var i = 0; i < ESize; i++)
                {
                    bytes[i] &= (byte)((bytes[i] >> 4) | ((bytes[i] & 0b00001111) << 4));
                }
                
                result = new BigInteger(
                    bytes,
                    isUnsigned: true,
                    isBigEndian: false);
                
                var isCoprime = CryptoMathService
                    .CalculateGcdEuclidean(result, n) == 1;
                
                if (isCoprime)
                    return;
            }
        }

        /// <summary>
        /// Calculates the private exponent 'd' for RSA using the extended Euclidean algorithm.
        /// </summary>
        /// <param name="result">Output parameter for the private exponent.</param>
        /// <param name="e">The public exponent of the RSA key, used to compute the private exponent 'd'.</param>
        /// <param name="eulerN">Euler's totient of the modulus.</param>
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
        
        #endregion
    }
}
