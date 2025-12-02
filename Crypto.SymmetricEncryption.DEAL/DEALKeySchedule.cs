using System.Runtime.InteropServices;
using Crypto.SymmetricEncryption.Base;

namespace Crypto.SymmetricEncryption;

/// <summary>
/// Implements the DEAL block cipher.
/// </summary>
public sealed partial class DEAL
{
    /// <summary>
    /// Implements a key schedule for the DEAL cipher using DES.
    /// Generates round keys based on the specified DEAL key size (128, 192, 256 bits).
    /// </summary>
    internal sealed class DEALKeySchedule : KeyScheduleBase
    {
        #region Fields

        private readonly DES _des;
        
        private readonly DealKeySize _dealKeySize;
        
        private readonly byte[] _keyForSchedule;

        #endregion


        #region Constructors     
        
        /// <summary>
        /// Implements a key schedule for the DEAL cipher using DES.
        /// Generates round keys based on the specified DEAL key size (128, 192, 256 bits).
        /// </summary>
        /// <param name="des">DES instance used for block encryption.</param>
        /// <param name="dealKeySize">Specifies the DEAL key size for round key generation.</param>
        /// <param name="keyForSchedule">Initial key bytes used to derive round keys.</param>
        public DEALKeySchedule(DES des,
            DealKeySize dealKeySize,
            byte[] keyForSchedule)
        {
            _des = des ?? throw new ArgumentNullException(nameof(des));
            _dealKeySize = dealKeySize;
            _keyForSchedule = keyForSchedule ?? throw new ArgumentNullException(nameof(keyForSchedule));
        }
        
        #endregion
        
        
        #region Methods

        /// <summary>
        /// Generates round keys for the DEAL cipher using DES and XOR operations.
        /// </summary>
        /// <param name="key">Memory of bytes representing the input key.</param>
        /// <returns>Jagged array of byte arrays containing the round keys.</returns>
        protected override byte[][] GenerateSchedule(Memory<byte> key)
        {
            if (key.IsEmpty)
                throw new ArgumentException("Key cannot be empty.", nameof(key));
            
            if (key.Length != _des.KeySize)
                throw new ArgumentOutOfRangeException(nameof(key), "Key size must be equal to the size of the deal.");

            var masterKeys = new Memory<byte>[key.Length / 8];
            for (var i = 0; i < key.Length / 8; i++)
            {
                masterKeys[i] = key.Slice(i * 8, 8);
            }

            switch (_dealKeySize)
            {
                case DealKeySize.Key128:
                {
                    var roundKeys = new byte[6][];
                    _des.EncryptBlock(
                        roundKeys[0] = masterKeys[0].ToArray());
                    _des.EncryptBlock(
                        roundKeys[1] = Xor(masterKeys[1], roundKeys[0]));
                    _des.EncryptBlock(
                        roundKeys[2] = Xor(masterKeys[0], roundKeys[1], 1));
                    _des.EncryptBlock(
                        roundKeys[3] = Xor(masterKeys[1], roundKeys[2], 2));
                    _des.EncryptBlock(
                        roundKeys[4] = Xor(masterKeys[0], roundKeys[3], 4));
                    _des.EncryptBlock(
                        roundKeys[5] = Xor(masterKeys[1], roundKeys[4], 8));
                    return roundKeys;
                }
                case DealKeySize.Key192:
                {
                    var roundKeys = new byte[6][];
                    _des.EncryptBlock(
                        roundKeys[0] = masterKeys[0].ToArray());
                    _des.EncryptBlock(
                        roundKeys[1] = Xor(masterKeys[1], roundKeys[0]));
                    _des.EncryptBlock(
                        roundKeys[2] = Xor(masterKeys[2], roundKeys[1]));
                    _des.EncryptBlock(
                        roundKeys[3] = Xor(masterKeys[0], roundKeys[2], 1));
                    _des.EncryptBlock(
                        roundKeys[4] = Xor(masterKeys[1], roundKeys[3], 2));
                    _des.EncryptBlock(
                        roundKeys[5] = Xor(masterKeys[2], roundKeys[4], 4));
                    return roundKeys;
                }
                case DealKeySize.Key256:
                {
                    var roundKeys = new byte[8][];
                    _des.EncryptBlock(
                        roundKeys[0] = masterKeys[0].ToArray());
                    _des.EncryptBlock(
                        roundKeys[1] = Xor(masterKeys[1], roundKeys[0]));
                    _des.EncryptBlock(
                        roundKeys[2] = Xor(masterKeys[2], roundKeys[1]));
                    _des.EncryptBlock(
                        roundKeys[3] = Xor(masterKeys[3], roundKeys[2]));
                    _des.EncryptBlock(
                        roundKeys[4] = Xor(masterKeys[0], roundKeys[3], 1));
                    _des.EncryptBlock(
                        roundKeys[5] = Xor(masterKeys[1], roundKeys[4], 2));
                    _des.EncryptBlock(
                        roundKeys[6] = Xor(masterKeys[2], roundKeys[5], 4));
                    _des.EncryptBlock(
                        roundKeys[7] = Xor(masterKeys[3], roundKeys[6], 8));
                    return roundKeys;
                }
                default:
                    throw new ArgumentException(
                        $"Invalid key size: {key.Length} bytes. Expected 16, 24, or 32 bytes.");
            }
        }

        /// <summary>
        /// Performs bitwise XOR between two 8-byte blocks.
        /// </summary>
        /// <param name="left">First 8-byte block.</param>
        /// <param name="right">Second 8-byte block.</param>
        /// <returns>Resulting 8-byte block after XOR.</returns>
        private static byte[] Xor(
            Memory<byte> left,
            Memory<byte> right)
        {
            if (left.Length != 8)
                throw new ArgumentException("Left block must be exactly 8 bytes.", nameof(left));

            if (right.Length != 8)
                throw new ArgumentException("Right block must be exactly 8 bytes.", nameof(right));
            
            var result = left.ToArray();
            MemoryMarshal.AsRef<ulong>(result) =
                MemoryMarshal.AsRef<ulong>(left.Span) ^
                MemoryMarshal.AsRef<ulong>(right.Span);
            return result;
        }

        /// <summary>
        /// Performs bitwise XOR between two 8-byte blocks and applies an additional mask.
        /// </summary>
        /// <param name="left">First 8-byte block.</param>
        /// <param name="right">Second 8-byte block.</param>
        /// <param name="mask">Mask to apply during XOR.</param>
        /// <returns>Resulting 8-byte block after XOR with mask.</returns>
        private static byte[] Xor(
            Memory<byte> left,
            Memory<byte> right,
            ulong mask)
        {
            if (left.Length != 8)
                throw new ArgumentException("Left block must be exactly 8 bytes.", nameof(left));

            if (right.Length != 8)
                throw new ArgumentException("Right block must be exactly 8 bytes.", nameof(right));
            
            var result = left.ToArray();
            MemoryMarshal.AsRef<ulong>(result) =
                MemoryMarshal.AsRef<ulong>(left.Span) ^
                MemoryMarshal.AsRef<ulong>(right.Span) ^
                mask;
            return result;
        }
        
        #endregion
    }
}